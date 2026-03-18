from __future__ import annotations

import hashlib
from typing import Iterable

from btc_models import BtcStratumJob, PreparedWork


DIFF1_TARGET = int(
    "00000000ffff0000000000000000000000000000000000000000000000000000", 16
)


def clean_hex(text: str) -> str:
    return "".join(ch for ch in (text or "").strip().lower() if ch in "0123456789abcdef")


def hex_to_bytes(text: str) -> bytes:
    t = clean_hex(text)
    if len(t) % 2 != 0:
        t = "0" + t
    return bytes.fromhex(t)


def reverse_hex_bytes(text: str) -> bytes:
    return hex_to_bytes(text)[::-1]


def swap_endian_words_bytes(text: str) -> bytes:
    raw = hex_to_bytes(text)
    if len(raw) % 4 != 0:
        raise ValueError("word-swapped hex must be 4-byte aligned")
    return b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))


def u32_to_le_bytes(value: int) -> bytes:
    return int(value & 0xFFFFFFFF).to_bytes(4, "little", signed=False)


def u32_to_submit_hex(value: int) -> str:
    """
    Submit the 4 raw header nonce bytes as hex, matching the bytes placed
    into the 80-byte header.
    """
    return u32_to_le_bytes(value).hex()


def dbl_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def difficulty_to_target_int(difficulty: float) -> int:
    d = float(difficulty)
    if d <= 0.0:
        return DIFF1_TARGET
    target = int(DIFF1_TARGET / d)
    return max(1, min(target, (1 << 256) - 1))


def target_int_to_hex(target: int) -> str:
    return f"{int(target):064x}"


def target_int_to_bytes_be(target: int) -> bytes:
    return int(target).to_bytes(32, "big", signed=False)


def hash_meets_target(hash_bytes_raw: bytes, target_int: int) -> bool:
    """
    Bitcoin compares the 32-byte digest as a little-endian integer to the target.
    """
    if len(hash_bytes_raw) != 32:
        return False
    return int.from_bytes(hash_bytes_raw, "little", signed=False) <= int(target_int)


def hash_to_display_hex(hash_bytes_raw: bytes) -> str:
    """
    Human-facing big-endian hex display.
    """
    if len(hash_bytes_raw) != 32:
        return hash_bytes_raw.hex()
    return hash_bytes_raw[::-1].hex()


def build_coinbase_tx(
    coinbase1_hex: str,
    extranonce1_hex: str,
    extranonce2_hex: str,
    coinbase2_hex: str,
) -> bytes:
    return (
        hex_to_bytes(coinbase1_hex)
        + hex_to_bytes(extranonce1_hex)
        + hex_to_bytes(extranonce2_hex)
        + hex_to_bytes(coinbase2_hex)
    )


def compute_merkle_root(coinbase_tx: bytes, merkle_branch_hex: Iterable[str]) -> bytes:
    node = dbl_sha256(coinbase_tx)
    for branch_hex in merkle_branch_hex:
        node = dbl_sha256(node + hex_to_bytes(branch_hex))
    return node


def build_header_prefix76(
    version_hex: str,
    prevhash_hex: str,
    merkle_root_raw: bytes,
    ntime_hex: str,
    nbits_hex: str,
) -> bytes:
    if len(merkle_root_raw) != 32:
        raise ValueError("merkle_root_raw must be 32 bytes")

    version_le = reverse_hex_bytes(version_hex)
    prevhash_le = swap_endian_words_bytes(prevhash_hex)
    merkle_root_le = merkle_root_raw[::-1]
    ntime_le = reverse_hex_bytes(ntime_hex)
    nbits_le = reverse_hex_bytes(nbits_hex)

    if len(version_le) != 4:
        raise ValueError(f"version_hex must be 4 bytes, got {version_hex!r}")
    if len(prevhash_le) != 32:
        raise ValueError(f"prevhash_hex must be 32 bytes, got {prevhash_hex!r}")
    if len(ntime_le) != 4:
        raise ValueError(f"ntime_hex must be 4 bytes, got {ntime_hex!r}")
    if len(nbits_le) != 4:
        raise ValueError(f"nbits_hex must be 4 bytes, got {nbits_hex!r}")

    return version_le + prevhash_le + merkle_root_le + ntime_le + nbits_le


def build_header80(header_prefix76: bytes, nonce: int) -> bytes:
    if len(header_prefix76) != 76:
        raise ValueError(f"header_prefix76 must be 76 bytes, got {len(header_prefix76)}")
    return header_prefix76 + u32_to_le_bytes(nonce)


def prepare_work(
    job: BtcStratumJob,
    extranonce1_hex: str,
    extranonce2_hex: str,
) -> PreparedWork:
    coinbase_tx = build_coinbase_tx(
        job.coinbase1_hex,
        extranonce1_hex,
        extranonce2_hex,
        job.coinbase2_hex,
    )
    merkle_root_raw = compute_merkle_root(coinbase_tx, job.merkle_branch_hex)
    header_prefix76 = build_header_prefix76(
        job.version_hex,
        job.prevhash_hex,
        merkle_root_raw,
        job.ntime_hex,
        job.nbits_hex,
    )
    return PreparedWork(
        job_id=job.job_id,
        extranonce2_hex=extranonce2_hex,
        ntime_hex=job.ntime_hex,
        coinbase_tx_hex=coinbase_tx.hex(),
        merkle_root_hex=hash_to_display_hex(merkle_root_raw),
        header_prefix76_hex=header_prefix76.hex(),
        header_prefix76=header_prefix76,
        share_target_int=job.share_target_int,
        share_target_hex=job.share_target_hex,
        share_target_bytes_be=target_int_to_bytes_be(job.share_target_int),
    )