from __future__ import annotations

import ctypes
import math
import os
import sys
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional

from btc_models import BtcMinerConfig, CandidateShare, PreparedWork


def _search_roots() -> list[str]:
    roots: list[str] = []

    try:
        roots.append(os.path.abspath(os.path.dirname(__file__)))
    except Exception:
        pass

    try:
        roots.append(os.path.abspath(os.getcwd()))
    except Exception:
        pass

    try:
        roots.append(os.path.abspath(os.path.dirname(sys.executable)))
    except Exception:
        pass

    try:
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            roots.append(os.path.abspath(meipass))
    except Exception:
        pass

    out: list[str] = []
    seen: set[str] = set()
    for root in roots:
        norm = os.path.normcase(os.path.abspath(root))
        if norm not in seen:
            seen.add(norm)
            out.append(os.path.abspath(root))
    return out


def _candidate_paths(path: str, default_name: str) -> list[str]:
    raw = (path or "").strip()
    roots = _search_roots()
    candidates: list[str] = []

    if raw:
        if os.path.isabs(raw):
            candidates.append(os.path.abspath(raw))
            basename = os.path.basename(raw)
            if basename:
                for root in roots:
                    candidates.append(os.path.abspath(os.path.join(root, basename)))
        else:
            for root in roots:
                candidates.append(os.path.abspath(os.path.join(root, raw)))
    else:
        for root in roots:
            candidates.append(os.path.abspath(os.path.join(root, default_name)))

    out: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        norm = os.path.normcase(os.path.abspath(candidate))
        if norm not in seen:
            seen.add(norm)
            out.append(os.path.abspath(candidate))
    return out


def _resolve_existing_path(path: str, default_name: str) -> str:
    candidates = _candidate_paths(path, default_name)
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    tried = "\n  ".join(candidates)
    raise FileNotFoundError(
        f"Could not locate {default_name!r}. Tried:\n  {tried}"
    )


def _align_up(value: int, align: int) -> int:
    value = int(value)
    align = max(1, int(align))
    return ((value + align - 1) // align) * align


@dataclass
class VirtualAsicKernelAnnotations:
    candidate_merge_mode: bool = False
    count_arg_index: int = -1
    merge_buffers: list[tuple[int, int]] = field(default_factory=list)
    partition_mode: str = ""
    partition_scalar_arg_index: int = -1

    def summary(self) -> str:
        merge_text = ",".join(f"{arg}:{size}" for arg, size in self.merge_buffers) or "-"
        part = self.partition_mode or "-"
        if self.partition_scalar_arg_index >= 0 and not part.endswith(f":{self.partition_scalar_arg_index}"):
            part = f"{part}:{self.partition_scalar_arg_index}"
        return (
            f"candidate_merge={'on' if self.candidate_merge_mode else 'off'} "
            f"count_arg={self.count_arg_index if self.count_arg_index >= 0 else '-'} "
            f"merge_buffers={merge_text} "
            f"partition={part}"
        )


def _parse_kernel_annotations(kernel_path: str) -> VirtualAsicKernelAnnotations:
    meta = VirtualAsicKernelAnnotations()

    try:
        with open(kernel_path, "r", encoding="utf-8", errors="replace") as f:
            for raw_line in f:
                line = raw_line.strip()
                if "@vasic_" not in line:
                    continue

                pos = line.find("@vasic_")
                cmd = line[pos + len("@vasic_"):].strip()

                if cmd.startswith("mode"):
                    value = cmd[len("mode"):].strip()
                    if value == "candidate_merge":
                        meta.candidate_merge_mode = True

                elif cmd.startswith("count_arg"):
                    value = cmd[len("count_arg"):].strip()
                    try:
                        meta.count_arg_index = int(value, 10)
                    except Exception:
                        pass

                elif cmd.startswith("merge_buffer"):
                    value = cmd[len("merge_buffer"):].strip()
                    if ":" in value:
                        left, right = value.split(":", 1)
                        try:
                            meta.merge_buffers.append((int(left.strip(), 10), int(right.strip(), 10)))
                        except Exception:
                            pass

                elif cmd.startswith("partition"):
                    value = cmd[len("partition"):].strip()
                    meta.partition_mode = value
                    if value.startswith("scalar_u32:"):
                        try:
                            meta.partition_scalar_arg_index = int(value.split(":", 1)[1].strip())
                        except Exception:
                            pass
                    elif value.startswith("global_offset+scalar_u32:"):
                        try:
                            meta.partition_scalar_arg_index = int(value.split(":", 1)[1].strip())
                        except Exception:
                            pass
    except Exception:
        pass

    return meta


class BitcoinVirtualAsicBridge:
    """
    Required VirtualASIC DLL exports:

        vasic_create_ex(uint32_t core_count) -> void*
        vasic_destroy(void*)
        vasic_copy_last_error(void*, char*, uint32_t) -> int

        vasic_create_buffer(void*, uint32_t size_bytes) -> uint32_t
        vasic_release_buffer(void*, uint32_t buffer_id) -> int
        vasic_write_buffer(void*, uint32_t buffer_id, uint32_t offset, const void* src, uint32_t size) -> int
        vasic_read_buffer(void*, uint32_t buffer_id, uint32_t offset, void* dst, uint32_t size) -> int

        vasic_load_kernel_file(void*, const char* kernel_name, const char* file_path) -> uint32_t
        vasic_release_kernel(void*, uint32_t kernel_id) -> int

        vasic_set_kernel_arg_buffer(void*, uint32_t kernel_id, uint32_t arg_index, uint32_t buffer_id) -> int
        vasic_set_kernel_arg_u32(void*, uint32_t kernel_id, uint32_t arg_index, uint32_t value) -> int

        vasic_enqueue_ndrange(void*, uint32_t kernel_id, uint32_t global_size) -> int
    """

    def __init__(
        self,
        dll_path: str,
        kernel_path: str,
        kernel_name: str,
        core_count: int,
        on_log: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.on_log = on_log or (lambda msg: None)

        self.dll_path = ""
        self.kernel_path = ""
        self.kernel_name = (kernel_name or "").strip()
        self.core_count = max(1, int(core_count))

        self.lib = None
        self.engine = None
        self.kernel_id = 0
        self.available = False
        self.load_error = ""
        self._dll_dir_handles: list[object] = []
        self._call_lock = threading.Lock()

        try:
            self.dll_path = _resolve_existing_path(dll_path, "VirtualASIC.dll")
            self.kernel_path = _resolve_existing_path(kernel_path, "btc_sha256d_scan.cl")
            self._prepare_dll_search_dirs(self.dll_path)

            if os.name == "nt":
                self.lib = ctypes.WinDLL(self.dll_path)
            else:
                self.lib = ctypes.CDLL(self.dll_path)

            self.lib.vasic_create_ex.argtypes = [ctypes.c_uint32]
            self.lib.vasic_create_ex.restype = ctypes.c_void_p

            self.lib.vasic_destroy.argtypes = [ctypes.c_void_p]
            self.lib.vasic_destroy.restype = None

            self.lib.vasic_copy_last_error.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
            self.lib.vasic_copy_last_error.restype = ctypes.c_int

            self.lib.vasic_create_buffer.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
            self.lib.vasic_create_buffer.restype = ctypes.c_uint32

            self.lib.vasic_release_buffer.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
            self.lib.vasic_release_buffer.restype = ctypes.c_int

            self.lib.vasic_write_buffer.argtypes = [
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.c_uint32,
            ]
            self.lib.vasic_write_buffer.restype = ctypes.c_int

            self.lib.vasic_read_buffer.argtypes = [
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.c_uint32,
            ]
            self.lib.vasic_read_buffer.restype = ctypes.c_int

            self.lib.vasic_load_kernel_file.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
            self.lib.vasic_load_kernel_file.restype = ctypes.c_uint32

            self.lib.vasic_release_kernel.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
            self.lib.vasic_release_kernel.restype = ctypes.c_int

            self.lib.vasic_set_kernel_arg_buffer.argtypes = [
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_uint32,
            ]
            self.lib.vasic_set_kernel_arg_buffer.restype = ctypes.c_int

            self.lib.vasic_set_kernel_arg_u32.argtypes = [
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_uint32,
            ]
            self.lib.vasic_set_kernel_arg_u32.restype = ctypes.c_int

            self.lib.vasic_enqueue_ndrange.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32]
            self.lib.vasic_enqueue_ndrange.restype = ctypes.c_int

            self.available = True
            self.on_log(f"[virtualasic] loaded {self.dll_path}")
        except Exception as exc:
            self.available = False
            self.load_error = str(exc)
            self.on_log(f"[virtualasic] unavailable: {exc}")

    def _prepare_dll_search_dirs(self, dll_path: str) -> None:
        if os.name != "nt":
            return

        dirs: list[str] = []
        dll_dir = os.path.abspath(os.path.dirname(dll_path))
        dirs.append(dll_dir)

        for root in _search_roots():
            dirs.append(os.path.abspath(root))

        seen: set[str] = set()
        for directory in dirs:
            if not directory or not os.path.isdir(directory):
                continue

            norm = os.path.normcase(os.path.abspath(directory))
            if norm in seen:
                continue
            seen.add(norm)

            try:
                if hasattr(os, "add_dll_directory"):
                    self._dll_dir_handles.append(os.add_dll_directory(directory))
            except Exception:
                pass

    def initialize(self) -> None:
        if not self.available or self.lib is None:
            raise RuntimeError("VirtualASIC DLL is not available")

        with self._call_lock:
            self.engine = self.lib.vasic_create_ex(ctypes.c_uint32(self.core_count))
        if not self.engine:
            raise RuntimeError("vasic_create_ex failed")

        kernel_name_b = self.kernel_name.encode("utf-8") if self.kernel_name else None
        kernel_path_b = self.kernel_path.encode("utf-8")

        with self._call_lock:
            self.kernel_id = int(self.lib.vasic_load_kernel_file(self.engine, kernel_name_b, kernel_path_b))
        if not self.kernel_id:
            err = self.last_error()
            self.close()
            raise RuntimeError(f"vasic_load_kernel_file failed: {err}")

        self.on_log(
            f"[virtualasic] engine created cores={self.core_count} "
            f"kernel={self.kernel_path} kernel_id={self.kernel_id}"
        )

    def close(self) -> None:
        try:
            if self.lib is not None and self.engine and self.kernel_id:
                try:
                    with self._call_lock:
                        self.lib.vasic_release_kernel(self.engine, ctypes.c_uint32(self.kernel_id))
                except Exception:
                    pass
        finally:
            self.kernel_id = 0

        if self.lib is not None and self.engine:
            try:
                with self._call_lock:
                    self.lib.vasic_destroy(self.engine)
            except Exception:
                pass
        self.engine = None

        for handle in self._dll_dir_handles:
            try:
                handle.close()
            except Exception:
                pass
        self._dll_dir_handles.clear()

    def last_error(self) -> str:
        if self.lib is None or not self.engine:
            return "unknown error"

        buf = ctypes.create_string_buffer(4096)
        try:
            with self._call_lock:
                self.lib.vasic_copy_last_error(self.engine, buf, ctypes.c_uint32(len(buf)))
            text = buf.value.decode("utf-8", errors="replace").strip()
            return text or "unknown error"
        except Exception:
            return "unknown error"

    def _check(self, ok: int, what: str) -> None:
        if int(ok) == 0:
            raise RuntimeError(f"{what} failed: {self.last_error()}")

    def create_buffer(self, size_bytes: int) -> int:
        if self.lib is None or not self.engine:
            raise RuntimeError("VirtualASIC engine is not initialized")
        with self._call_lock:
            bid = int(self.lib.vasic_create_buffer(self.engine, ctypes.c_uint32(int(size_bytes))))
        if bid == 0:
            raise RuntimeError(f"vasic_create_buffer failed: {self.last_error()}")
        return bid

    def release_buffer(self, buffer_id: int) -> None:
        if self.lib is None or not self.engine or not buffer_id:
            return
        with self._call_lock:
            ok = self.lib.vasic_release_buffer(self.engine, ctypes.c_uint32(int(buffer_id)))
        self._check(
            ok,
            f"vasic_release_buffer(buffer_id={buffer_id})",
        )

    def write_buffer(self, buffer_id: int, data: bytes, offset: int = 0) -> None:
        if self.lib is None or not self.engine:
            raise RuntimeError("VirtualASIC engine is not initialized")

        src = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        with self._call_lock:
            ok = self.lib.vasic_write_buffer(
                self.engine,
                ctypes.c_uint32(int(buffer_id)),
                ctypes.c_uint32(int(offset)),
                src,
                ctypes.c_uint32(len(data)),
            )
        self._check(
            ok,
            f"vasic_write_buffer(buffer_id={buffer_id}, size={len(data)}, offset={offset})",
        )

    def read_buffer(self, buffer_id: int, size_bytes: int, offset: int = 0) -> bytes:
        if self.lib is None or not self.engine:
            raise RuntimeError("VirtualASIC engine is not initialized")

        dst = (ctypes.c_ubyte * int(size_bytes))()
        with self._call_lock:
            ok = self.lib.vasic_read_buffer(
                self.engine,
                ctypes.c_uint32(int(buffer_id)),
                ctypes.c_uint32(int(offset)),
                dst,
                ctypes.c_uint32(int(size_bytes)),
            )
        self._check(
            ok,
            f"vasic_read_buffer(buffer_id={buffer_id}, size={size_bytes}, offset={offset})",
        )
        return bytes(dst)

    def set_arg_buffer(self, arg_index: int, buffer_id: int) -> None:
        if self.lib is None or not self.engine or not self.kernel_id:
            raise RuntimeError("VirtualASIC engine is not initialized")

        with self._call_lock:
            ok = self.lib.vasic_set_kernel_arg_buffer(
                self.engine,
                ctypes.c_uint32(self.kernel_id),
                ctypes.c_uint32(int(arg_index)),
                ctypes.c_uint32(int(buffer_id)),
            )
        self._check(
            ok,
            f"vasic_set_kernel_arg_buffer(arg_index={arg_index}, buffer_id={buffer_id})",
        )

    def set_arg_u32(self, arg_index: int, value: int) -> None:
        if self.lib is None or not self.engine or not self.kernel_id:
            raise RuntimeError("VirtualASIC engine is not initialized")

        with self._call_lock:
            ok = self.lib.vasic_set_kernel_arg_u32(
                self.engine,
                ctypes.c_uint32(self.kernel_id),
                ctypes.c_uint32(int(arg_index)),
                ctypes.c_uint32(int(value) & 0xFFFFFFFF),
            )
        self._check(
            ok,
            f"vasic_set_kernel_arg_u32(arg_index={arg_index}, value={int(value) & 0xFFFFFFFF})",
        )

    def enqueue(self, global_size: int) -> None:
        if self.lib is None or not self.engine or not self.kernel_id:
            raise RuntimeError("VirtualASIC engine is not initialized")

        with self._call_lock:
            ok = self.lib.vasic_enqueue_ndrange(
                self.engine,
                ctypes.c_uint32(self.kernel_id),
                ctypes.c_uint32(int(global_size)),
            )
        self._check(
            ok,
            f"vasic_enqueue_ndrange(global_size={global_size})",
        )


class VirtualAsicSha256dScanner:
    """
    Expected kernel arg contract for btc_sha256d_scan.cl:

        arg 0: buffer prefix76       (76 bytes)
        arg 1: buffer target32_be    (32 bytes)
        arg 2: buffer out_nonces     (max_results * 4 bytes, little-endian u32s)
        arg 3: buffer out_hashes_be  (max_results * 32 bytes)
        arg 4: buffer out_count      (4 bytes, little-endian u32)
        arg 5: u32    start_nonce
        arg 6: u32    max_results

    This rewrite activates CPU-lane-friendly behavior without changing the DLL by:
      - reading kernel annotations
      - using a larger launch window for candidate_merge kernels
      - caching the overscanned nonce range so later worker calls do not overlap
    """

    ARG_PREFIX76 = 0
    ARG_TARGET32 = 1
    ARG_OUT_NONCES = 2
    ARG_OUT_HASHES = 3
    ARG_OUT_COUNT = 4
    ARG_START_NONCE = 5
    ARG_MAX_RESULTS = 6

    def __init__(self, config: BtcMinerConfig, on_log: Callable[[str], None]) -> None:
        self.config = config
        self.on_log = on_log

        self.bridge: Optional[BitcoinVirtualAsicBridge] = None
        self.annotations = VirtualAsicKernelAnnotations()

        self._prefix_buf = 0
        self._target_buf = 0
        self._out_nonces_buf = 0
        self._out_hashes_buf = 0
        self._out_count_buf = 0
        self._out_capacity = 0

        self._hybrid_force_enable = bool(getattr(self.config, "virtualasic_force_cpu_lane", True))
        self._hybrid_min_launch = max(1, int(getattr(self.config, "virtualasic_hybrid_min_launch", 8192)))
        self._hybrid_align = max(1, int(getattr(self.config, "virtualasic_hybrid_align", 256)))
        self._hybrid_max_results_cap = max(1, int(getattr(self.config, "virtualasic_hybrid_max_results_cap", 4096)))

        self._cache_work_key: Optional[tuple] = None
        self._cache_range_start: int = 0
        self._cache_range_end: int = 0
        self._cache_hits: list[CandidateShare] = []

    def initialize(self) -> None:
        self.bridge = BitcoinVirtualAsicBridge(
            dll_path=self.config.virtualasic_dll_path,
            kernel_path=self.config.virtualasic_kernel_path,
            kernel_name=self.config.virtualasic_kernel_name,
            core_count=self.config.virtualasic_core_count,
            on_log=self.on_log,
        )
        if not self.bridge.available:
            raise RuntimeError("VirtualASIC DLL could not be loaded")

        self.annotations = _parse_kernel_annotations(self.bridge.kernel_path)
        self.on_log(f"[virtualasic] kernel annotations {self.annotations.summary()}")

        self.bridge.initialize()

        self._prefix_buf = self.bridge.create_buffer(76)
        self._target_buf = self.bridge.create_buffer(32)

        self.bridge.set_arg_buffer(self.ARG_PREFIX76, self._prefix_buf)
        self.bridge.set_arg_buffer(self.ARG_TARGET32, self._target_buf)

        if self._is_hybrid_candidate_merge_kernel():
            self.on_log(
                f"[virtualasic] cpu-lane assist enabled "
                f"min_launch={self._hybrid_min_launch} align={self._hybrid_align}"
            )
        else:
            self.on_log("[virtualasic] cpu-lane assist disabled for this kernel")

        self.on_log(
            f"[virtualasic] ready kernel={self.config.virtualasic_kernel_name or '(file-defined)'} "
            f"cores={self.config.virtualasic_core_count}"
        )

    def close(self) -> None:
        self._clear_cache()

        if self.bridge is None:
            return

        for buffer_id in (
            self._out_count_buf,
            self._out_hashes_buf,
            self._out_nonces_buf,
            self._target_buf,
            self._prefix_buf,
        ):
            if buffer_id:
                try:
                    self.bridge.release_buffer(buffer_id)
                except Exception:
                    pass

        self._prefix_buf = 0
        self._target_buf = 0
        self._out_nonces_buf = 0
        self._out_hashes_buf = 0
        self._out_count_buf = 0
        self._out_capacity = 0

        try:
            self.bridge.close()
        finally:
            self.bridge = None

    def _clear_cache(self) -> None:
        self._cache_work_key = None
        self._cache_range_start = 0
        self._cache_range_end = 0
        self._cache_hits = []

    def _work_key(self, work: PreparedWork) -> tuple:
        return (
            work.job_id,
            work.extranonce2_hex,
            work.ntime_hex,
            bytes(work.header_prefix76),
            bytes(work.share_target_bytes_be),
        )

    def _is_hybrid_candidate_merge_kernel(self) -> bool:
        if not self._hybrid_force_enable:
            return False
        if not self.annotations.candidate_merge_mode:
            return False
        if self.annotations.count_arg_index != self.ARG_OUT_COUNT:
            return False

        merge_map = {(arg, size) for arg, size in self.annotations.merge_buffers}
        expected = {
            (self.ARG_OUT_NONCES, 4),
            (self.ARG_OUT_HASHES, 32),
        }
        if not expected.issubset(merge_map):
            return False

        part = self.annotations.partition_mode or ""
        if not (
            part == ""
            or part == "global_offset"
            or part.startswith("scalar_u32:")
            or part.startswith("global_offset+scalar_u32:")
        ):
            return False

        return True

    def _ensure_output_buffers(self, max_results: int) -> None:
        if self.bridge is None:
            raise RuntimeError("VirtualASIC scanner is not initialized")

        if (
            self._out_capacity >= max_results
            and self._out_nonces_buf
            and self._out_hashes_buf
            and self._out_count_buf
        ):
            return

        for buffer_id in (self._out_nonces_buf, self._out_hashes_buf, self._out_count_buf):
            if buffer_id:
                try:
                    self.bridge.release_buffer(buffer_id)
                except Exception:
                    pass

        self._out_nonces_buf = self.bridge.create_buffer(max_results * 4)
        self._out_hashes_buf = self.bridge.create_buffer(max_results * 32)
        self._out_count_buf = self.bridge.create_buffer(4)

        self.bridge.set_arg_buffer(self.ARG_OUT_NONCES, self._out_nonces_buf)
        self.bridge.set_arg_buffer(self.ARG_OUT_HASHES, self._out_hashes_buf)
        self.bridge.set_arg_buffer(self.ARG_OUT_COUNT, self._out_count_buf)

        self._out_capacity = max_results

    def _filter_hits_for_range(
        self,
        hits: list[CandidateShare],
        start_nonce: int,
        end_nonce: int,
        max_results: int,
    ) -> list[CandidateShare]:
        out: list[CandidateShare] = []
        for share in hits:
            nonce = int(getattr(share, "nonce", 0)) & 0xFFFFFFFF
            if start_nonce <= nonce < end_nonce:
                out.append(share)
                if len(out) >= max_results:
                    break
        return out

    def _hits_sorted(self, hits: list[CandidateShare]) -> list[CandidateShare]:
        return sorted(hits, key=lambda s: int(getattr(s, "nonce", 0)) & 0xFFFFFFFF)

    def _select_launch_count(self, requested_count: int) -> int:
        launch_count = max(1, int(requested_count))

        if self._is_hybrid_candidate_merge_kernel() and launch_count < self._hybrid_min_launch:
            launch_count = self._hybrid_min_launch

        launch_count = _align_up(launch_count, self._hybrid_align)
        launch_count = min(launch_count, 0x100000000)
        return max(1, int(launch_count))

    def _select_launch_max_results(self, requested_count: int, launch_count: int, max_results: int) -> int:
        requested_count = max(1, int(requested_count))
        launch_count = max(1, int(launch_count))
        base = max(1, int(max_results))

        if launch_count <= requested_count:
            return base

        ratio = int(math.ceil(float(launch_count) / float(requested_count)))
        scaled = max(base, base * ratio)
        return min(self._hybrid_max_results_cap, scaled)

    def _run_kernel(
        self,
        work: PreparedWork,
        start_nonce: int,
        count: int,
        max_results: int,
    ) -> list[CandidateShare]:
        if self.bridge is None:
            raise RuntimeError("VirtualASIC scanner is not initialized")

        self._ensure_output_buffers(max_results)

        self.bridge.write_buffer(self._prefix_buf, work.header_prefix76)
        self.bridge.write_buffer(self._target_buf, work.share_target_bytes_be)
        self.bridge.write_buffer(self._out_count_buf, (0).to_bytes(4, "little", signed=False))

        self.bridge.set_arg_u32(self.ARG_START_NONCE, int(start_nonce) & 0xFFFFFFFF)
        self.bridge.set_arg_u32(self.ARG_MAX_RESULTS, max_results)
        self.bridge.enqueue(count)

        found_raw = self.bridge.read_buffer(self._out_count_buf, 4)
        found = min(int.from_bytes(found_raw, "little", signed=False), max_results)
        if found <= 0:
            return []

        nonce_bytes = self.bridge.read_buffer(self._out_nonces_buf, found * 4)
        hash_bytes = self.bridge.read_buffer(self._out_hashes_buf, found * 32)

        rows: list[CandidateShare] = []
        for i in range(found):
            nonce = int.from_bytes(nonce_bytes[i * 4:(i + 1) * 4], "little", signed=False)
            hash_be = hash_bytes[i * 32:(i + 1) * 32].hex()
            rows.append(
                CandidateShare(
                    job_id=work.job_id,
                    extranonce2_hex=work.extranonce2_hex,
                    ntime_hex=work.ntime_hex,
                    nonce=nonce,
                    header_hash_hex=hash_be,
                )
            )
        return self._hits_sorted(rows)

    def scan(
        self,
        work: PreparedWork,
        start_nonce: int,
        count: int,
        max_results: int,
    ) -> list[CandidateShare]:
        if self.bridge is None:
            raise RuntimeError("VirtualASIC scanner is not initialized")

        if len(work.header_prefix76) != 76:
            raise ValueError("PreparedWork.header_prefix76 must be 76 bytes")
        if len(work.share_target_bytes_be) != 32:
            raise ValueError("PreparedWork.share_target_bytes_be must be 32 bytes")

        count = max(0, int(count))
        max_results = max(1, int(max_results))
        if count <= 0:
            return []

        work_key = self._work_key(work)
        req_start = int(start_nonce) & 0xFFFFFFFF
        req_end = req_start + count

        if self._cache_work_key != work_key:
            self._clear_cache()

        results: list[CandidateShare] = []

        if (
            self._cache_work_key == work_key
            and self._cache_range_start <= req_start < self._cache_range_end
        ):
            overlap_end = min(req_end, self._cache_range_end)
            cached = self._filter_hits_for_range(self._cache_hits, req_start, overlap_end, max_results)
            results.extend(cached)

            if overlap_end >= req_end or len(results) >= max_results:
                return results[:max_results]

            req_start = overlap_end

        available_space = 0x100000000 - req_start
        if available_space <= 0:
            return results[:max_results]

        launch_count = self._select_launch_count(req_end - req_start)
        launch_count = min(launch_count, available_space)

        launch_max_results = self._select_launch_max_results(req_end - req_start, launch_count, max_results)
        launch_max_results = max(launch_max_results, max_results)


        launched_hits = self._run_kernel(
            work=work,
            start_nonce=req_start,
            count=launch_count,
            max_results=launch_max_results,
        )

        self._cache_work_key = work_key
        self._cache_range_start = req_start
        self._cache_range_end = req_start + launch_count
        self._cache_hits = launched_hits

        fresh = self._filter_hits_for_range(self._cache_hits, req_start, req_end, max_results - len(results))
        results.extend(fresh)

        return results[:max_results]