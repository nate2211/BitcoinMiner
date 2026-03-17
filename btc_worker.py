from __future__ import annotations

import threading
import time
from typing import Callable, Optional

from btc_models import BtcMinerConfig, BtcStratumJob, PreparedWork
from btc_native import BitcoinNativeBridge
from btc_opencl_scanner import OpenCLSha256dScanner
from btc_reference_scanner import CpuExactSha256dScanner
from btc_stratum_connection import BitcoinStratumConnection
from btc_utils import build_header80, dbl_sha256, hash_meets_target, hash_to_display_hex, prepare_work


class BitcoinMinerWorker:
    def __init__(
        self,
        config: BtcMinerConfig,
        on_log: Optional[Callable[[str], None]] = None,
        on_status: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.config = config
        self.on_log = on_log or (lambda msg: print(msg, flush=True))
        self.on_status = on_status or (lambda status: print(f"[status] {status}", flush=True))

        self._stop = threading.Event()
        self._job_lock = threading.Lock()

        self._current_job: Optional[BtcStratumJob] = None
        self._prepared_work: Optional[PreparedWork] = None
        self._nonce_cursor: int = 0
        self._extranonce2_counter: int = 0
        self._last_job_at: float = 0.0

        self.native = BitcoinNativeBridge(self.config.native_dll_path, self.on_log)

        self.client = BitcoinStratumConnection(
            config=config,
            on_log=self.on_log,
            on_job=self._on_job,
            on_status=self.on_status,
        )

        self.scanner = self._make_scanner()
        self.verifier = CpuExactSha256dScanner(self.on_log, native=self.native if self.native.available else None)
        self.verifier.initialize()

    def _make_scanner(self):
        backend = self.config.normalized_scan_backend()

        if backend in {"opencl", "auto"}:
            try:
                scanner = OpenCLSha256dScanner(self.config, self.on_log)
                scanner.initialize()
                self.on_log("[worker] scanner=opencl")
                return scanner
            except Exception as exc:
                self.on_log(f"[worker] opencl unavailable: {exc}")

        if backend in {"native", "auto"} and self.native.available:
            scanner = CpuExactSha256dScanner(self.on_log, native=self.native)
            scanner.initialize()
            self.on_log("[worker] scanner=native")
            return scanner

        scanner = CpuExactSha256dScanner(self.on_log, native=self.native if self.native.available else None)
        scanner.initialize()
        self.on_log("[worker] scanner=python")
        return scanner

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        self.client.connect()

        try:
            while not self._stop.is_set():
                if not self.client.alive:
                    raise RuntimeError(f"stratum connection lost: {self.client.fatal_error or 'disconnected'}")

                now = time.time()
                if self._last_job_at > 0 and (now - self._last_job_at) > 120:
                    raise RuntimeError("no mining.notify received for 120 seconds")

                job, work = self._get_job_and_work()

                if job is None:
                    time.sleep(float(self.config.idle_sleep_s))
                    continue

                if work is None:
                    work = self._prepare_next_work(job)

                count = max(1, int(self.config.scan_window_nonces))
                max_results = max(1, int(self.config.max_results_per_scan))

                with self._job_lock:
                    start_nonce = self._nonce_cursor
                    if start_nonce + count >= 0x100000000:
                        self._prepared_work = None
                        self._nonce_cursor = 0
                        self.on_log(f"[worker] nonce space exhausted for job={job.job_id}; rolling extranonce2")
                        continue
                    self._nonce_cursor += count

                self.on_log(
                    f"[scan] job={job.job_id} extranonce2={work.extranonce2_hex} "
                    f"start_nonce={start_nonce:08x} count={count}"
                )

                found = self.scanner.scan(
                    work=work,
                    start_nonce=start_nonce,
                    count=count,
                    max_results=max_results,
                )

                if not found:
                    continue

                for share in found:
                    if self._is_stale_share(share.job_id):
                        self.on_log(
                            f"[submit] stale-skip job={share.job_id} nonce={share.nonce:08x} reason=current job changed"
                        )
                        continue

                    verified_hash_hex = self._verify_share_exact(work, share.nonce)
                    if not verified_hash_hex:
                        self.on_log(
                            f"[submit] verify-failed job={share.job_id} nonce={share.nonce:08x} "
                            f"reason=candidate did not meet target on exact recheck"
                        )
                        continue

                    result = self.client.submit(share)
                    if result.accepted:
                        self.on_log(
                            f"[submit] accepted job={share.job_id} "
                            f"nonce={share.nonce:08x} hash={verified_hash_hex}"
                        )
                    else:
                        self.on_log(
                            f"[submit] rejected job={share.job_id} "
                            f"nonce={share.nonce:08x} error={result.error or result.status}"
                        )

        finally:
            try:
                self.client.close()
            finally:
                try:
                    self.scanner.close()
                except Exception:
                    pass
                try:
                    self.verifier.close()
                except Exception:
                    pass

    def _on_job(self, job: BtcStratumJob) -> None:
        with self._job_lock:
            self._current_job = job
            self._prepared_work = None
            self._nonce_cursor = 0
            self._last_job_at = time.time()

            if job.clean_jobs:
                self._extranonce2_counter = 0

        self.on_log(
            f"[worker] new_job job_id={job.job_id} clean={job.clean_jobs} target={job.share_target_hex}"
        )

    def _get_job_and_work(self) -> tuple[Optional[BtcStratumJob], Optional[PreparedWork]]:
        with self._job_lock:
            return self._current_job, self._prepared_work

    def _prepare_next_work(self, job: BtcStratumJob) -> PreparedWork:
        extranonce1 = self.client.session.extranonce1_hex
        extranonce2_size = int(self.client.session.extranonce2_size)

        if not extranonce1 or extranonce2_size <= 0:
            raise RuntimeError("Stratum session is missing extranonce state")

        max_value = 1 << (8 * extranonce2_size)
        value = self._extranonce2_counter % max_value
        extranonce2_hex = value.to_bytes(extranonce2_size, "big", signed=False).hex()

        work = prepare_work(
            job=job,
            extranonce1_hex=extranonce1,
            extranonce2_hex=extranonce2_hex,
        )

        with self._job_lock:
            if self._current_job is not None and self._current_job.job_id == job.job_id:
                self._prepared_work = work
                self._nonce_cursor = 0
                self._extranonce2_counter += 1

        self.on_log(
            f"[work] prepared job={job.job_id} extranonce2={extranonce2_hex} "
            f"merkle_root={work.merkle_root_hex}"
        )
        return work

    def _is_stale_share(self, share_job_id: str) -> bool:
        with self._job_lock:
            current_job_id = self._current_job.job_id if self._current_job is not None else None
        return current_job_id != share_job_id

    def _verify_share_exact(self, work: PreparedWork, nonce: int) -> str:
        header80 = build_header80(work.header_prefix76, nonce)

        if self.native is not None and self.native.available:
            raw_hash = self.native.sha256d_header80(header80)
        else:
            raw_hash = dbl_sha256(header80)

        if not hash_meets_target(raw_hash, work.share_target_int):
            return ""

        return hash_to_display_hex(raw_hash)