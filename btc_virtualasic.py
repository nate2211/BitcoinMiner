from __future__ import annotations

import ctypes
import os
import sys
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


class BitcoinVirtualAsicBridge:
    """
    Expected VirtualASIC DLL exports:

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

        try:
            self.dll_path = _resolve_existing_path(dll_path, "VirtualASIC.dll")
            self.kernel_path = _resolve_existing_path(kernel_path, "btc_sha256d_scan.cl")
            self._prepare_dll_search_dirs(self.dll_path)

            self.lib = ctypes.CDLL(self.dll_path)
            self._bind()
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

    def _bind(self) -> None:
        assert self.lib is not None

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

    def initialize(self) -> None:
        if not self.available or self.lib is None:
            raise RuntimeError("VirtualASIC DLL is not available")

        self.engine = self.lib.vasic_create_ex(ctypes.c_uint32(self.core_count))
        if not self.engine:
            raise RuntimeError("vasic_create_ex failed")

        kernel_name_b = self.kernel_name.encode("utf-8") if self.kernel_name else None
        kernel_path_b = self.kernel_path.encode("utf-8")

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
                    self.lib.vasic_release_kernel(self.engine, ctypes.c_uint32(self.kernel_id))
                except Exception:
                    pass
        finally:
            self.kernel_id = 0

        if self.lib is not None and self.engine:
            try:
                self.lib.vasic_destroy(self.engine)
            except Exception:
                pass
        self.engine = None
        self.lib = self.lib

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
        bid = int(self.lib.vasic_create_buffer(self.engine, ctypes.c_uint32(int(size_bytes))))
        if bid == 0:
            raise RuntimeError(f"vasic_create_buffer failed: {self.last_error()}")
        return bid

    def release_buffer(self, buffer_id: int) -> None:
        if self.lib is None or not self.engine or not buffer_id:
            return
        self._check(
            self.lib.vasic_release_buffer(self.engine, ctypes.c_uint32(int(buffer_id))),
            f"vasic_release_buffer(buffer_id={buffer_id})",
        )

    def write_buffer(self, buffer_id: int, data: bytes, offset: int = 0) -> None:
        if self.lib is None or not self.engine:
            raise RuntimeError("VirtualASIC engine is not initialized")

        src = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        self._check(
            self.lib.vasic_write_buffer(
                self.engine,
                ctypes.c_uint32(int(buffer_id)),
                ctypes.c_uint32(int(offset)),
                src,
                ctypes.c_uint32(len(data)),
            ),
            f"vasic_write_buffer(buffer_id={buffer_id}, size={len(data)}, offset={offset})",
        )

    def read_buffer(self, buffer_id: int, size_bytes: int, offset: int = 0) -> bytes:
        if self.lib is None or not self.engine:
            raise RuntimeError("VirtualASIC engine is not initialized")

        dst = (ctypes.c_ubyte * int(size_bytes))()
        self._check(
            self.lib.vasic_read_buffer(
                self.engine,
                ctypes.c_uint32(int(buffer_id)),
                ctypes.c_uint32(int(offset)),
                dst,
                ctypes.c_uint32(int(size_bytes)),
            ),
            f"vasic_read_buffer(buffer_id={buffer_id}, size={size_bytes}, offset={offset})",
        )
        return bytes(dst)

    def set_arg_buffer(self, arg_index: int, buffer_id: int) -> None:
        if self.lib is None or not self.engine or not self.kernel_id:
            raise RuntimeError("VirtualASIC engine is not initialized")

        self._check(
            self.lib.vasic_set_kernel_arg_buffer(
                self.engine,
                ctypes.c_uint32(self.kernel_id),
                ctypes.c_uint32(int(arg_index)),
                ctypes.c_uint32(int(buffer_id)),
            ),
            f"vasic_set_kernel_arg_buffer(arg_index={arg_index}, buffer_id={buffer_id})",
        )

    def set_arg_u32(self, arg_index: int, value: int) -> None:
        if self.lib is None or not self.engine or not self.kernel_id:
            raise RuntimeError("VirtualASIC engine is not initialized")

        self._check(
            self.lib.vasic_set_kernel_arg_u32(
                self.engine,
                ctypes.c_uint32(self.kernel_id),
                ctypes.c_uint32(int(arg_index)),
                ctypes.c_uint32(int(value) & 0xFFFFFFFF),
            ),
            f"vasic_set_kernel_arg_u32(arg_index={arg_index}, value={int(value) & 0xFFFFFFFF})",
        )

    def enqueue(self, global_size: int) -> None:
        if self.lib is None or not self.engine or not self.kernel_id:
            raise RuntimeError("VirtualASIC engine is not initialized")

        self._check(
            self.lib.vasic_enqueue_ndrange(
                self.engine,
                ctypes.c_uint32(self.kernel_id),
                ctypes.c_uint32(int(global_size)),
            ),
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

    global_size passed to enqueue_ndrange == nonce count for the scan window.
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
        self._prefix_buf = 0
        self._target_buf = 0
        self._out_nonces_buf = 0
        self._out_hashes_buf = 0
        self._out_count_buf = 0
        self._out_capacity = 0

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

        self.bridge.initialize()

        self._prefix_buf = self.bridge.create_buffer(76)
        self._target_buf = self.bridge.create_buffer(32)

        self.bridge.set_arg_buffer(self.ARG_PREFIX76, self._prefix_buf)
        self.bridge.set_arg_buffer(self.ARG_TARGET32, self._target_buf)

        self.on_log(
            f"[virtualasic] ready kernel={self.config.virtualasic_kernel_name or '(file-defined)'} "
            f"cores={self.config.virtualasic_core_count}"
        )

    def close(self) -> None:
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

    def _ensure_output_buffers(self, max_results: int) -> None:
        if self.bridge is None:
            raise RuntimeError("VirtualASIC scanner is not initialized")

        if (
            self._out_capacity == max_results
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
        return rows