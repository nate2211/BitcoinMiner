from __future__ import annotations

from typing import Callable, Optional

from btc_models import CandidateShare, PreparedWork
from btc_native import BitcoinNativeBridge
from btc_utils import build_header80, dbl_sha256, hash_meets_target, hash_to_display_hex


class CpuExactSha256dScanner:
    def __init__(
        self,
        on_log: Callable[[str], None],
        native: Optional[BitcoinNativeBridge] = None,
    ) -> None:
        self.on_log = on_log
        self.native = native

    def initialize(self) -> None:
        pass

    def close(self) -> None:
        pass

    def scan(
        self,
        work: PreparedWork,
        start_nonce: int,
        count: int,
        max_results: int,
    ) -> list[CandidateShare]:
        if self.native is not None and self.native.available:
            rows = self.native.scan_prefix76(
                prefix76=work.header_prefix76,
                start_nonce=start_nonce,
                count=count,
                target32_be=work.share_target_bytes_be,
                max_results=max_results,
            )
            return [
                CandidateShare(
                    job_id=work.job_id,
                    extranonce2_hex=work.extranonce2_hex,
                    ntime_hex=work.ntime_hex,
                    nonce=nonce,
                    header_hash_hex=hash_hex_be,
                )
                for nonce, hash_hex_be in rows
            ]

        results: list[CandidateShare] = []
        end_nonce = min(0x100000000, int(start_nonce) + int(count))

        for nonce in range(int(start_nonce), end_nonce):
            header80 = build_header80(work.header_prefix76, nonce)
            raw_hash = dbl_sha256(header80)
            if hash_meets_target(raw_hash, work.share_target_int):
                results.append(
                    CandidateShare(
                        job_id=work.job_id,
                        extranonce2_hex=work.extranonce2_hex,
                        ntime_hex=work.ntime_hex,
                        nonce=nonce,
                        header_hash_hex=hash_to_display_hex(raw_hash),
                    )
                )
                if len(results) >= max_results:
                    break

        return results