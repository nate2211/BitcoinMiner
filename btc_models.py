from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class BtcMinerConfig:
    # Pool / Stratum
    host: str = "btc.hiveon.com"
    port: int = 4444
    login: str = "bc1qp55qrhrrqt47d62w6x3me4alx70gqqsgkaew00.worker"
    password: str = "x"
    agent: str = "OpenCL-BTC/0.2"
    use_tls: bool = False

    socket_timeout_s: float = 60.0
    submit_timeout_s: float = 15.0

    # Scanner backend: "opencl" | "native" | "python" | "auto"
    scan_backend: str = "opencl"

    # Native DLL
    native_dll_path: str = "BitcoinProject.dll"

    # OpenCL
    opencl_loader: str = "OpenCL.dll"
    kernel_path: str = "btc_sha256d_scan.cl"
    build_options: str = "-cl-std=CL1.2"
    platform_index: int = 0
    device_index: int = 0
    local_work_size: Optional[int] = 128

    # Mining loop
    scan_window_nonces: int = 1_048_576
    max_results_per_scan: int = 8
    idle_sleep_s: float = 0.10

    def normalized_scan_backend(self) -> str:
        text = (self.scan_backend or "opencl").strip().lower()
        if text in {"opencl", "native", "python", "auto"}:
            return text
        return "opencl"


@dataclass
class StratumSession:
    extranonce1_hex: str = ""
    extranonce2_size: int = 0
    subscribed: bool = False
    authorized: bool = False


@dataclass
class BtcStratumJob:
    job_id: str
    prevhash_hex: str
    coinbase1_hex: str
    coinbase2_hex: str
    merkle_branch_hex: list[str]
    version_hex: str
    nbits_hex: str
    ntime_hex: str
    clean_jobs: bool

    share_difficulty: float = 1.0
    share_target_int: int = 0
    share_target_hex: str = ""

    received_at: float = field(default_factory=time.time)


@dataclass
class PreparedWork:
    job_id: str
    extranonce2_hex: str
    ntime_hex: str
    coinbase_tx_hex: str
    merkle_root_hex: str
    header_prefix76_hex: str
    header_prefix76: bytes

    share_target_int: int
    share_target_hex: str
    share_target_bytes_be: bytes


@dataclass
class CandidateShare:
    job_id: str
    extranonce2_hex: str
    ntime_hex: str
    nonce: int
    header_hash_hex: str


@dataclass
class SubmitResult:
    accepted: bool
    status: str = ""
    error: str = ""
    raw: Any = None