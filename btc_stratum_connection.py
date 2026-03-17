from __future__ import annotations

import json
import queue
import socket
import ssl
import threading
from typing import Callable, Optional

from btc_models import BtcMinerConfig, BtcStratumJob, CandidateShare, StratumSession, SubmitResult
from btc_utils import difficulty_to_target_int, target_int_to_hex, u32_to_submit_hex


class BitcoinStratumConnection:
    def __init__(
        self,
        config: BtcMinerConfig,
        on_log: Callable[[str], None],
        on_job: Callable[[BtcStratumJob], None],
        on_status: Callable[[str], None],
    ) -> None:
        self.config = config
        self.on_log = on_log
        self.on_job = on_job
        self.on_status = on_status

        self.session = StratumSession()

        self._sock: Optional[socket.socket] = None
        self._reader_thread: Optional[threading.Thread] = None
        self._send_lock = threading.Lock()
        self._stop = threading.Event()

        self._rpc_id = 1
        self._pending: dict[int, "queue.Queue[dict]"] = {}
        self._pending_lock = threading.Lock()

        self._share_difficulty = 1.0
        self._recv_buffer = b""
        self._alive = False
        self._fatal_error: str = ""

    @property
    def alive(self) -> bool:
        return self._alive and not self._stop.is_set()

    @property
    def fatal_error(self) -> str:
        return self._fatal_error

    def connect(self) -> None:
        self._stop.clear()
        self._recv_buffer = b""
        self._fatal_error = ""
        self._alive = False

        raw = socket.create_connection(
            (self.config.host, self.config.port),
            timeout=float(self.config.socket_timeout_s),
        )

        try:
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass

        if self.config.use_tls:
            ctx = ssl.create_default_context()
            raw = ctx.wrap_socket(raw, server_hostname=self.config.host)

        # IMPORTANT:
        # do not use makefile()+readline() on a timed socket here.
        # Use raw recv() and line buffering ourselves.
        raw.settimeout(None)

        self._sock = raw
        self._alive = True

        self._reader_thread = threading.Thread(
            target=self._reader_loop,
            name="BtcStratumReader",
            daemon=True,
        )
        self._reader_thread.start()

        self.on_status("connecting")
        self.on_log(
            f"[stratum] connected host={self.config.host} port={self.config.port} tls={self.config.use_tls}"
        )

        try:
            self._rpc("mining.extranonce.subscribe", [], timeout=5.0)
        except Exception:
            pass

        sub = self._rpc("mining.subscribe", [self.config.agent], timeout=15.0)
        self._handle_subscribe_result(sub)

        auth = self._rpc("mining.authorize", [self.config.login, self.config.password], timeout=15.0)
        if not bool(auth.get("result")):
            raise RuntimeError(f"authorization failed: {auth}")

        self.session.authorized = True
        self.on_status("authorized")
        self.on_log(
            f"[stratum] authorized login={self.config.login} extranonce2_size={self.session.extranonce2_size}"
        )

    def close(self) -> None:
        self._stop.set()
        self._alive = False

        try:
            if self._sock is not None:
                try:
                    self._sock.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                self._sock.close()
        except Exception:
            pass

        if self._reader_thread is not None:
            try:
                self._reader_thread.join(timeout=2.0)
            except Exception:
                pass

        self._sock = None
        self._reader_thread = None
        self.on_status("closed")

    def submit(self, share: CandidateShare) -> SubmitResult:
        try:
            resp = self._rpc(
                "mining.submit",
                [
                    self.config.login,
                    share.job_id,
                    share.extranonce2_hex,
                    share.ntime_hex,
                    u32_to_submit_hex(share.nonce),
                ],
                timeout=float(self.config.submit_timeout_s),
            )
            accepted = bool(resp.get("result"))
            err = resp.get("error")
            return SubmitResult(
                accepted=accepted,
                status="accepted" if accepted else "rejected",
                error="" if accepted else (str(err) if err else ""),
                raw=resp,
            )
        except Exception as exc:
            return SubmitResult(
                accepted=False,
                status="error",
                error=str(exc),
                raw=None,
            )

    def _handle_subscribe_result(self, msg: dict) -> None:
        result = msg.get("result")
        if not isinstance(result, list) or len(result) < 3:
            raise RuntimeError(f"unexpected subscribe result: {msg!r}")

        extranonce1 = str(result[1] or "")
        extranonce2_size = int(result[2])

        self.session.extranonce1_hex = extranonce1
        self.session.extranonce2_size = extranonce2_size
        self.session.subscribed = True

        self.on_log(
            f"[stratum] subscribed extranonce1={extranonce1} extranonce2_size={extranonce2_size}"
        )

    def _rpc(self, method: str, params: list, timeout: float) -> dict:
        q: "queue.Queue[dict]" = queue.Queue(maxsize=1)

        with self._pending_lock:
            req_id = self._rpc_id
            self._rpc_id += 1
            self._pending[req_id] = q

        payload = {"id": req_id, "method": method, "params": params}
        self._send_json(payload)

        try:
            return q.get(timeout=timeout)
        finally:
            with self._pending_lock:
                self._pending.pop(req_id, None)

    def _send_json(self, payload: dict) -> None:
        raw = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
        if self._sock is None:
            raise RuntimeError("socket is not connected")
        with self._send_lock:
            self._sock.sendall(raw)

    def _reader_loop(self) -> None:
        while not self._stop.is_set():
            try:
                if self._sock is None:
                    break

                chunk = self._sock.recv(4096)
                if not chunk:
                    self._alive = False
                    if not self._stop.is_set():
                        self.on_status("disconnected")
                    break

                self._recv_buffer += chunk

                while b"\n" in self._recv_buffer:
                    line, self._recv_buffer = self._recv_buffer.split(b"\n", 1)
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        msg = json.loads(line.decode("utf-8"))
                    except Exception as exc:
                        self.on_log(f"[stratum] invalid json line ignored: {exc} raw={line!r}")
                        continue

                    self._handle_message(msg)

            except Exception as exc:
                self._alive = False
                self._fatal_error = str(exc)
                if not self._stop.is_set():
                    self.on_log(f"[stratum] reader error: {exc}")
                    self.on_status("error")
                break

    def _handle_message(self, msg: dict) -> None:
        if "method" in msg and msg.get("method"):
            self._handle_notification(msg)
            return

        msg_id = msg.get("id")
        if msg_id is None:
            return

        try:
            msg_id = int(msg_id)
        except Exception:
            return

        with self._pending_lock:
            q = self._pending.get(msg_id)
        if q is not None:
            try:
                q.put_nowait(msg)
            except queue.Full:
                pass

    def _handle_notification(self, msg: dict) -> None:
        method = str(msg.get("method") or "")
        params = msg.get("params") or []

        if method == "mining.set_difficulty":
            if params:
                self._share_difficulty = float(params[0])
                self.on_log(f"[stratum] set_difficulty={self._share_difficulty}")
            return

        if method == "mining.set_extranonce":
            if len(params) >= 2:
                self.session.extranonce1_hex = str(params[0] or "")
                self.session.extranonce2_size = int(params[1])
                self.on_log(
                    f"[stratum] set_extranonce extranonce1={self.session.extranonce1_hex} "
                    f"extranonce2_size={self.session.extranonce2_size}"
                )
            return

        if method == "mining.notify":
            if len(params) < 9:
                self.on_log(f"[stratum] short mining.notify ignored: {msg!r}")
                return

            job_id = str(params[0])
            prevhash_hex = str(params[1])
            coinbase1_hex = str(params[2])
            coinbase2_hex = str(params[3])
            merkle_branch_hex = [str(x) for x in params[4]]
            version_hex = str(params[5])
            nbits_hex = str(params[6])
            ntime_hex = str(params[7])
            clean_jobs = bool(params[8])

            target_int = difficulty_to_target_int(self._share_difficulty)
            job = BtcStratumJob(
                job_id=job_id,
                prevhash_hex=prevhash_hex,
                coinbase1_hex=coinbase1_hex,
                coinbase2_hex=coinbase2_hex,
                merkle_branch_hex=merkle_branch_hex,
                version_hex=version_hex,
                nbits_hex=nbits_hex,
                ntime_hex=ntime_hex,
                clean_jobs=clean_jobs,
                share_difficulty=self._share_difficulty,
                share_target_int=target_int,
                share_target_hex=target_int_to_hex(target_int),
            )

            self.on_log(
                f"[stratum] notify job_id={job.job_id} clean={job.clean_jobs} diff={job.share_difficulty}"
            )
            self.on_job(job)
            return

        self.on_log(f"[stratum] unhandled method={method} msg={msg!r}")