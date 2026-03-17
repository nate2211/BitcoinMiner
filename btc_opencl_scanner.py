from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass
from typing import Callable, Optional

import numpy as np
import pyopencl as cl

from btc_models import BtcMinerConfig, CandidateShare, PreparedWork


@dataclass
class OpenCLDeviceInfo:
    platform_index: int
    device_index: int
    platform_name: str
    device_name: str


def _resolve_path(path: str) -> str:
    if os.path.isabs(path):
        return path
    return os.path.abspath(path)


class OpenCLSha256dScanner:
    def __init__(self, config: BtcMinerConfig, on_log: Callable[[str], None]) -> None:
        self.config = config
        self.on_log = on_log

        self.ctx: Optional[cl.Context] = None
        self.queue: Optional[cl.CommandQueue] = None
        self.program: Optional[cl.Program] = None
        self.kernel = None
        self.device = None

        self._out_nonces_buf: Optional[cl.Buffer] = None
        self._out_hashes_buf: Optional[cl.Buffer] = None
        self._out_count_buf: Optional[cl.Buffer] = None

        self._out_nonces_np: Optional[np.ndarray] = None
        self._out_hashes_np: Optional[np.ndarray] = None
        self._out_count_np: Optional[np.ndarray] = None

        self._out_capacity: int = 0
        self._effective_local_work_size: Optional[int] = None

    @staticmethod
    def list_devices() -> list[OpenCLDeviceInfo]:
        out: list[OpenCLDeviceInfo] = []
        for p_idx, platform in enumerate(cl.get_platforms()):
            for d_idx, device in enumerate(platform.get_devices()):
                out.append(
                    OpenCLDeviceInfo(
                        platform_index=p_idx,
                        device_index=d_idx,
                        platform_name=platform.name.strip(),
                        device_name=device.name.strip(),
                    )
                )
        return out

    def initialize(self) -> None:
        self._ensure_opencl_loader()

        platforms = cl.get_platforms()
        if not platforms:
            raise RuntimeError("No OpenCL platforms found")

        if self.config.platform_index >= len(platforms):
            raise RuntimeError(f"Platform index out of range: {self.config.platform_index}")

        platform = platforms[self.config.platform_index]
        devices = platform.get_devices()
        if not devices:
            raise RuntimeError("No OpenCL devices found on selected platform")

        if self.config.device_index >= len(devices):
            raise RuntimeError(f"Device index out of range: {self.config.device_index}")

        device = devices[self.config.device_index]
        self.device = device
        self.ctx = cl.Context(devices=[device])
        self.queue = cl.CommandQueue(self.ctx, device=device)
        self.program = self._build_program(self.ctx, self.config.kernel_path, self.config.build_options)
        self.kernel = getattr(self.program, "btc_sha256d_scan")
        self._effective_local_work_size = self._choose_local_work_size()

        self.on_log(
            f"[opencl] using {platform.name.strip()} / {device.name.strip()} "
            f"lws={self._effective_local_work_size or 'auto'}"
        )

    def close(self) -> None:
        for buf_name in ("_out_nonces_buf", "_out_hashes_buf", "_out_count_buf"):
            buf = getattr(self, buf_name)
            if buf is not None:
                try:
                    buf.release()
                except Exception:
                    pass
                setattr(self, buf_name, None)

        self._out_nonces_np = None
        self._out_hashes_np = None
        self._out_count_np = None
        self._out_capacity = 0

    def scan(
        self,
        work: PreparedWork,
        start_nonce: int,
        count: int,
        max_results: int,
    ) -> list[CandidateShare]:
        if not all([self.ctx, self.queue, self.program, self.kernel]):
            raise RuntimeError("OpenCL scanner is not initialized")

        if len(work.header_prefix76) != 76:
            raise ValueError("PreparedWork.header_prefix76 must be 76 bytes")
        if len(work.share_target_bytes_be) != 32:
            raise ValueError("PreparedWork.share_target_bytes_be must be 32 bytes")

        count = max(0, int(count))
        max_results = max(1, int(max_results))
        if count <= 0:
            return []

        self._ensure_output_buffers(max_results)
        self._reset_out_count()

        mf = cl.mem_flags
        prefix_np = np.frombuffer(work.header_prefix76, dtype=np.uint8)
        target_np = np.frombuffer(work.share_target_bytes_be, dtype=np.uint8)

        prefix_buf = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=prefix_np)
        target_buf = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=target_np)

        lws = self._launch_local_size(count)
        if lws is None:
            global_work = (count,)
            local_work = None
        else:
            rounded = ((count + lws - 1) // lws) * lws
            global_work = (rounded,)
            local_work = (lws,)

        evt = self.kernel(
            self.queue,
            global_work,
            local_work,
            prefix_buf,
            np.uint32(count),
            np.uint32(start_nonce & 0xFFFFFFFF),
            target_buf,
            np.uint32(max_results),
            self._out_nonces_buf,
            self._out_hashes_buf,
            self._out_count_buf,
        )
        evt.wait()

        cl.enqueue_copy(self.queue, self._out_count_np, self._out_count_buf).wait()
        found = min(int(self._out_count_np[0]), max_results)

        results: list[CandidateShare] = []
        if found > 0:
            cl.enqueue_copy(self.queue, self._out_nonces_np[:found], self._out_nonces_buf).wait()
            cl.enqueue_copy(self.queue, self._out_hashes_np[:found, :], self._out_hashes_buf).wait()

            for i in range(found):
                results.append(
                    CandidateShare(
                        job_id=work.job_id,
                        extranonce2_hex=work.extranonce2_hex,
                        ntime_hex=work.ntime_hex,
                        nonce=int(self._out_nonces_np[i]),
                        header_hash_hex=bytes(self._out_hashes_np[i]).hex(),
                    )
                )

        try:
            prefix_buf.release()
        except Exception:
            pass
        try:
            target_buf.release()
        except Exception:
            pass

        return results

    def _ensure_opencl_loader(self) -> None:
        loader = _resolve_path(self.config.opencl_loader)
        if os.name == "nt":
            ctypes.WinDLL(loader)
            self.on_log(f"[opencl] loaded {loader}")

    def _build_program(self, ctx: cl.Context, kernel_path: str, build_options: str) -> cl.Program:
        resolved = _resolve_path(kernel_path)
        if not os.path.exists(resolved):
            raise FileNotFoundError(f"OpenCL kernel not found: {resolved}")

        with open(resolved, "r", encoding="utf-8", errors="replace") as f:
            src = f.read()

        prg = cl.Program(ctx, src)
        try:
            opts = build_options.split() if (build_options or "").strip() else []
            prg.build(options=opts)
        except Exception as exc:
            build_log = ""
            try:
                if self.device is not None:
                    build_log = prg.get_build_info(self.device, cl.program_build_info.LOG) or ""
            except Exception:
                pass
            raise RuntimeError(f"OpenCL build failed: {exc}\n{build_log}") from exc
        return prg

    def _choose_local_work_size(self) -> Optional[int]:
        requested = self.config.local_work_size
        if requested is None or int(requested) <= 0:
            requested = 128

        if self.device is None:
            return int(requested)

        try:
            max_wg = int(getattr(self.device, "max_work_group_size", requested))
        except Exception:
            max_wg = int(requested)

        requested = max(1, min(int(requested), max_wg))
        return requested

    def _launch_local_size(self, count: int) -> Optional[int]:
        lws = self._effective_local_work_size
        if lws is None or lws <= 0:
            return None
        return int(lws)

    def _ensure_output_buffers(self, max_results: int) -> None:
        if self.ctx is None:
            raise RuntimeError("OpenCL scanner is not initialized")

        if (
            self._out_nonces_buf is not None
            and self._out_hashes_buf is not None
            and self._out_count_buf is not None
            and self._out_capacity == max_results
        ):
            return

        for buf_name in ("_out_nonces_buf", "_out_hashes_buf", "_out_count_buf"):
            buf = getattr(self, buf_name)
            if buf is not None:
                try:
                    buf.release()
                except Exception:
                    pass
                setattr(self, buf_name, None)

        mf = cl.mem_flags
        self._out_nonces_np = np.empty((max_results,), dtype=np.uint32)
        self._out_hashes_np = np.empty((max_results, 32), dtype=np.uint8)
        self._out_count_np = np.zeros((1,), dtype=np.uint32)

        self._out_nonces_buf = cl.Buffer(self.ctx, mf.WRITE_ONLY, self._out_nonces_np.nbytes)
        self._out_hashes_buf = cl.Buffer(self.ctx, mf.WRITE_ONLY, self._out_hashes_np.nbytes)
        self._out_count_buf = cl.Buffer(self.ctx, mf.READ_WRITE, self._out_count_np.nbytes)
        self._out_capacity = max_results

    def _reset_out_count(self) -> None:
        if self.queue is None or self._out_count_buf is None:
            raise RuntimeError("Output buffers are not initialized")
        zero = np.zeros((1,), dtype=np.uint32)
        cl.enqueue_copy(self.queue, self._out_count_buf, zero).wait()