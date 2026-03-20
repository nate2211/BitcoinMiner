from __future__ import annotations

import collections
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from btc_models import BtcMinerConfig, BtcStratumJob, CandidateShare, PreparedWork
from btc_native import BitcoinNativeBridge
from btc_opencl_scanner import OpenCLSha256dScanner
from btc_reference_scanner import CpuExactSha256dScanner
from btc_stratum_connection import BitcoinStratumConnection
from btc_utils import build_header80, dbl_sha256, hash_meets_target, hash_to_display_hex, prepare_work


@dataclass
class _StatsSnapshot:
    accepted: int = 0
    rejected: int = 0
    errors: int = 0
    verify_failed: int = 0
    verified_before_submit: int = 0
    stale_skipped: int = 0


class _HashrateTracker:
    def __init__(self, window_s: float) -> None:
        self.window_s = max(1.0, float(window_s))
        self.samples: collections.deque[tuple[float, int]] = collections.deque()

    def add(self, nonce_count: int) -> None:
        now = time.time()
        c = max(0, int(nonce_count))
        self.samples.append((now, c))
        self._trim(now)

    def rate_hs(self) -> float:
        now = time.time()
        self._trim(now)
        if not self.samples:
            return 0.0
        total = sum(v for _, v in self.samples)
        dt = max(0.001, now - self.samples[0][0])
        return total / dt

    def _trim(self, now: float) -> None:
        cutoff = now - self.window_s
        while self.samples and self.samples[0][0] < cutoff:
            self.samples.popleft()


def _format_hashrate(hs: float) -> str:
    units = ["H/s", "kH/s", "MH/s", "GH/s", "TH/s", "PH/s"]
    value = float(hs)
    idx = 0
    while value >= 1000.0 and idx < len(units) - 1:
        value /= 1000.0
        idx += 1
    return f"{value:.2f} {units[idx]}"


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

        self._stats = _StatsSnapshot()
        self._hashrate = _HashrateTracker(window_s=float(self.config.stats_window_s))
        self._last_stats_log_at = 0.0

        self.native = BitcoinNativeBridge(self.config.native_dll_path, self.on_log)

        self.client = BitcoinStratumConnection(
            config=config,
            on_log=self.on_log,
            on_job=self._on_job,
            on_status=self.on_status,
            on_session_update=self._on_session_update,
        )

        self._scanner_kind = "python"
        self.scanner = self._make_scanner()

        verify_mode = "on" if self._should_verify_opencl_hits() else "off"
        self.on_log(
            f"[worker] scanner={self._scanner_kind} verify_opencl_hits_before_submit={verify_mode}"
        )

    def _make_scanner(self):
        backend = self.config.normalized_scan_backend()

        if backend in {"opencl", "auto"}:
            try:
                scanner = OpenCLSha256dScanner(self.config, self.on_log)
                scanner.initialize()
                self._scanner_kind = "opencl"
                return scanner
            except Exception as exc:
                self.on_log(f"[worker] opencl unavailable: {exc}")

        if backend in {"native", "auto"} and self.native.available:
            scanner = CpuExactSha256dScanner(self.on_log, native=self.native)
            scanner.initialize()
            self._scanner_kind = "native"
            return scanner

        scanner = CpuExactSha256dScanner(self.on_log, native=self.native if self.native.available else None)
        scanner.initialize()
        self._scanner_kind = "python"
        return scanner

    def _should_verify_opencl_hits(self) -> bool:
        return self._scanner_kind == "opencl" and bool(self.config.verify_opencl_hits_before_submit)

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        backoff = max(0.25, float(self.config.reconnect_initial_delay_s))
        next_host = self.config.host
        next_port = int(self.config.port)

        try:
            while not self._stop.is_set():
                try:
                    self.client.connect(host_override=next_host, port_override=next_port)
                    self.on_status("running")
                    self._session_loop()
                    backoff = max(0.25, float(self.config.reconnect_initial_delay_s))
                except Exception as exc:
                    if self._stop.is_set():
                        break
                    self.on_log(f"[worker] session error: {exc}")
                finally:
                    try:
                        self.client.close()
                    except Exception:
                        pass
                    with self._job_lock:
                        self._current_job = None
                        self._prepared_work = None
                        self._nonce_cursor = 0

                if self._stop.is_set():
                    break

                requested = self.client.consume_reconnect_request()
                if requested is not None:
                    next_host, next_port, wait_s = requested
                    sleep_s = max(0.0, float(wait_s))
                    self.on_log(
                        f"[worker] reconnect requested host={next_host} port={next_port} wait={sleep_s:.1f}s"
                    )
                    backoff = max(0.25, float(self.config.reconnect_initial_delay_s))
                else:
                    next_host = self.config.host
                    next_port = int(self.config.port)
                    sleep_s = backoff
                    backoff = min(float(self.config.reconnect_max_delay_s), max(backoff * 2.0, 1.0))

                self.on_status("reconnecting")
                time.sleep(sleep_s)
        finally:
            try:
                self.scanner.close()
            except Exception:
                pass

    def _session_loop(self) -> None:
        while not self._stop.is_set():
            if not self.client.alive:
                raise RuntimeError(f"stratum connection lost: {self.client.fatal_error or 'disconnected'}")

            idle_reconnect_s = float(self.config.idle_reconnect_s)
            if idle_reconnect_s > 0.0 and self.client.seconds_since_recv() > idle_reconnect_s:
                raise RuntimeError(f"no stratum traffic for {idle_reconnect_s:.0f}s")

            job, work = self._get_job_and_work()

            if job is None:
                self._maybe_log_stats()
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
                f"[scan] backend={self._scanner_kind} job={job.job_id} "
                f"extranonce2={work.extranonce2_hex} start_nonce={start_nonce:08x} count={count}"
            )

            scan_t0 = time.time()
            found = self.scanner.scan(
                work=work,
                start_nonce=start_nonce,
                count=count,
                max_results=max_results,
            )
            scan_dt = max(0.000001, time.time() - scan_t0)
            self._hashrate.add(count)
            self._maybe_log_stats(inst_hs=(count / scan_dt))

            if not found:
                continue

            verify_before_submit = self._should_verify_opencl_hits()

            for share in found:
                if self._is_stale_share(share.job_id):
                    self._stats.stale_skipped += 1
                    self.on_log(
                        f"[submit] stale-skip job={share.job_id} nonce={share.nonce:08x} "
                        f"reason=current job changed"
                    )
                    continue

                final_hash_hex = (share.header_hash_hex or "").strip().lower()

                if verify_before_submit:
                    verified_hash_hex, verify_note = self._verify_share_exact(work, share)
                    if not verified_hash_hex:
                        self._stats.verify_failed += 1
                        self.on_log(
                            f"[submit] verify-failed job={share.job_id} nonce={share.nonce:08x} "
                            f"reason=exact cpu/native recheck did not meet share target"
                        )
                        continue

                    self._stats.verified_before_submit += 1
                    final_hash_hex = verified_hash_hex

                    if verify_note:
                        self.on_log(
                            f"[verify] job={share.job_id} nonce={share.nonce:08x} note={verify_note}"
                        )

                result = self.client.submit(share)
                if result.accepted:
                    self._stats.accepted += 1
                    self.on_log(
                        f"[submit] accepted job={share.job_id} nonce={share.nonce:08x} hash={final_hash_hex}"
                    )
                else:
                    if result.status == "error":
                        self._stats.errors += 1
                    else:
                        self._stats.rejected += 1
                    self.on_log(
                        f"[submit] rejected job={share.job_id} nonce={share.nonce:08x} "
                        f"error={result.error or result.status}"
                    )

    def _on_job(self, job: BtcStratumJob) -> None:
        with self._job_lock:
            if job.clean_jobs:
                self._prepared_work = None
                self._nonce_cursor = 0
                self._extranonce2_counter = 0
            self._current_job = job

        self.on_log(
            f"[worker] new_job job_id={job.job_id} clean={job.clean_jobs} target={job.share_target_hex}"
        )

    def _on_session_update(self, reason: str) -> None:
        with self._job_lock:
            self._prepared_work = None
            self._nonce_cursor = 0
            if reason == "extranonce":
                self._extranonce2_counter = 0
        self.on_log(f"[worker] session_update reason={reason} work reset")

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

    def _verify_share_exact(self, work: PreparedWork, share: CandidateShare) -> tuple[str, str]:
        header80 = build_header80(work.header_prefix76, share.nonce)

        if self.native is not None and self.native.available:
            raw_hash = self.native.sha256d_header80(header80)
        else:
            raw_hash = dbl_sha256(header80)

        if not hash_meets_target(raw_hash, work.share_target_int):
            return "", ""

        exact_hash_hex = hash_to_display_hex(raw_hash)
        gpu_hash_hex = (share.header_hash_hex or "").strip().lower()

        if gpu_hash_hex and gpu_hash_hex != exact_hash_hex:
            return exact_hash_hex, f"gpu/cpu hash mismatch gpu={gpu_hash_hex} cpu={exact_hash_hex}; using cpu/native result"

        return exact_hash_hex, ""

    def _maybe_log_stats(self, inst_hs: Optional[float] = None) -> None:
        now = time.time()
        every = max(1.0, float(self.config.stats_log_interval_s))
        if (now - self._last_stats_log_at) < every:
            return
        self._last_stats_log_at = now

        avg_hs = self._hashrate.rate_hs()
        inst_text = _format_hashrate(inst_hs if inst_hs is not None else avg_hs)
        avg_text = _format_hashrate(avg_hs)

        self.on_log(
            "[stats] "
            f"inst={inst_text} "
            f"avg{int(self.config.stats_window_s)}={avg_text} "
            f"accepted={self._stats.accepted} "
            f"rejected={self._stats.rejected} "
            f"errors={self._stats.errors} "
            f"verified={self._stats.verified_before_submit} "
            f"verify_failed={self._stats.verify_failed} "
            f"stale={self._stats.stale_skipped}"
        )