from __future__ import annotations

import ctypes
import os
import sys
import threading
from typing import Callable, Optional


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


class BitcoinNativeBridge:
    def __init__(self, dll_path: str, on_log: Optional[Callable[[str], None]] = None) -> None:
        self.on_log = on_log or (lambda msg: None)

        self.dll_path = ""
        self.lib = None
        self.available = False
        self.load_error = ""
        self._dll_dir_handles: list[object] = []
        self._call_lock = threading.Lock()

        try:
            self.dll_path = _resolve_existing_path(dll_path, "BitcoinProject.dll")
            self._prepare_dll_search_dirs(self.dll_path)

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
            self.load_error = str(exc)
            self.on_log(f"[native] unavailable: {exc}")

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

    def sha256d_header80(self, header80: bytes) -> bytes:
        if not self.available or self.lib is None:
            raise RuntimeError("BitcoinProject DLL is not available")
        if len(header80) != 80:
            raise ValueError("header80 must be exactly 80 bytes")

        in_arr = (ctypes.c_ubyte * 80).from_buffer_copy(header80)
        out_arr = (ctypes.c_ubyte * 32)()

        with self._call_lock:
            rc = self.lib.btc_sha256d_header80(in_arr, out_arr)

        if rc != 0:
            raise RuntimeError(f"btc_sha256d_header80 failed: rc={rc}")

        return bytes(out_arr)

    def sha256d_many_header80(self, headers80: list[bytes]) -> list[bytes]:
        out: list[bytes] = []
        for header80 in headers80:
            out.append(self.sha256d_header80(header80))
        return out

    def sha256d_prefix76_nonce(self, prefix76: bytes, nonce: int) -> bytes:
        if len(prefix76) != 76:
            raise ValueError("prefix76 must be exactly 76 bytes")
        nonce_le = int(nonce & 0xFFFFFFFF).to_bytes(4, "little", signed=False)
        return self.sha256d_header80(prefix76 + nonce_le)

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

        max_results = max(1, int(max_results))

        prefix_arr = (ctypes.c_ubyte * 76).from_buffer_copy(prefix76)
        target_arr = (ctypes.c_ubyte * 32).from_buffer_copy(target32_be)

        out_nonces = (ctypes.c_uint32 * max_results)()
        out_hashes = (ctypes.c_ubyte * (max_results * 32))()
        out_count = ctypes.c_uint32(0)

        with self._call_lock:
            rc = self.lib.btc_scan_prefix76(
                prefix_arr,
                ctypes.c_uint32(int(start_nonce) & 0xFFFFFFFF),
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
        n = min(int(out_count.value), max_results)
        for i in range(n):
            base = i * 32
            hash_be = bytes(out_hashes[base:base + 32]).hex()
            rows.append((int(out_nonces[i]), hash_be))
        return rows

    def close(self) -> None:
        self.lib = None
        self.available = False

        for handle in self._dll_dir_handles:
            try:
                handle.close()
            except Exception:
                pass
        self._dll_dir_handles.clear()