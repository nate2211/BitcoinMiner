from __future__ import annotations

import ctypes
import os
from typing import Callable, Optional


def _resolve_path(path: str) -> str:
    if os.path.isabs(path):
        return path
    return os.path.abspath(path)


class BitcoinNativeBridge:
    def __init__(self, dll_path: str, on_log: Optional[Callable[[str], None]] = None) -> None:
        self.dll_path = _resolve_path(dll_path)
        self.on_log = on_log or (lambda msg: None)

        self.lib = None
        self.available = False

        try:
            if os.name == "nt":
                self.lib = ctypes.WinDLL(self.dll_path)
            else:
                self.lib = ctypes.CDLL(self.dll_path)

            u8_p = ctypes.POINTER(ctypes.c_ubyte)
            u32_p = ctypes.POINTER(ctypes.c_uint32)

            self.lib.btc_sha256d_header80.argtypes = [u8_p, u8_p]
            self.lib.btc_sha256d_header80.restype = ctypes.c_int

            self.lib.btc_scan_prefix76.argtypes = [
                u8_p,                 # prefix76
                ctypes.c_uint32,      # start_nonce
                ctypes.c_uint32,      # count
                u8_p,                 # target32_be
                ctypes.c_uint32,      # max_results
                u32_p,                # out_nonces
                u8_p,                 # out_hashes32_be
                u32_p,                # out_count
            ]
            self.lib.btc_scan_prefix76.restype = ctypes.c_int

            self.available = True
            self.on_log(f"[native] loaded {self.dll_path}")
        except Exception as exc:
            self.available = False
            self.on_log(f"[native] unavailable: {exc}")

    def sha256d_header80(self, header80: bytes) -> bytes:
        if not self.available or self.lib is None:
            raise RuntimeError("BitcoinProject DLL is not available")
        if len(header80) != 80:
            raise ValueError("header80 must be exactly 80 bytes")

        in_arr = (ctypes.c_ubyte * 80).from_buffer_copy(header80)
        out_arr = (ctypes.c_ubyte * 32)()
        rc = self.lib.btc_sha256d_header80(in_arr, out_arr)
        if rc != 0:
            raise RuntimeError(f"btc_sha256d_header80 failed: rc={rc}")
        return bytes(out_arr)

    def scan_prefix76(
        self,
        prefix76: bytes,
        start_nonce: int,
        count: int,
        target32_be: bytes,
        max_results: int,
    ) -> list[tuple[int, str]]:
        if not self.available or self.lib is None:
            raise RuntimeError("BitcoinProject DLL is not available")
        if len(prefix76) != 76:
            raise ValueError("prefix76 must be exactly 76 bytes")
        if len(target32_be) != 32:
            raise ValueError("target32_be must be exactly 32 bytes")

        prefix_arr = (ctypes.c_ubyte * 76).from_buffer_copy(prefix76)
        target_arr = (ctypes.c_ubyte * 32).from_buffer_copy(target32_be)

        out_nonces = (ctypes.c_uint32 * max_results)()
        out_hashes = (ctypes.c_ubyte * (max_results * 32))()
        out_count = ctypes.c_uint32(0)

        rc = self.lib.btc_scan_prefix76(
            prefix_arr,
            ctypes.c_uint32(start_nonce & 0xFFFFFFFF),
            ctypes.c_uint32(max(0, int(count))),
            target_arr,
            ctypes.c_uint32(max_results),
            out_nonces,
            out_hashes,
            ctypes.byref(out_count),
        )
        if rc != 0:
            raise RuntimeError(f"btc_scan_prefix76 failed: rc={rc}")

        rows: list[tuple[int, str]] = []
        n = min(int(out_count.value), int(max_results))
        for i in range(n):
            base = i * 32
            hash_be = bytes(out_hashes[base:base + 32]).hex()
            rows.append((int(out_nonces[i]), hash_be))
        return rows