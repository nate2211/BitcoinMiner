from __future__ import annotations

import json
import queue
import socket
import ssl
import threading
import time
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
        on_session_update: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.config = config
        self.on_log = on_log
        self.on_job = on_job
        self.on_status = on_status
        self.on_session_update = on_session_update or (lambda reason: None)

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
        self._last_recv_at: float = 0.0

        self._current_host = config.host
        self._current_port = int(config.port)
        self._requested_reconnect: Optional[tuple[str, int, float]] = None
        self._closing_for_reconnect = False

    @property
    def alive(self) -> bool:
        return self._alive and not self._stop.is_set()

    @property
    def fatal_error(self) -> str:
        return self._fatal_error

    def seconds_since_recv(self) -> float:
        if self._last_recv_at <= 0.0:
            return 0.0
        return max(0.0, time.time() - self._last_recv_at)

    def consume_reconnect_request(self) -> Optional[tuple[str, int, float]]:
        req = self._requested_reconnect
        self._requested_reconnect = None
        return req

    def connect(self, host_override: Optional[str] = None, port_override: Optional[int] = None) -> None:
        self._stop.clear()
        self._recv_buffer = b""
        self._fatal_error = ""
        self._alive = False
        self._last_recv_at = 0.0
        self._requested_reconnect = None
        self._closing_for_reconnect = False

        self.session = StratumSession()

        self._current_host = (host_override or self.config.host).strip()
        self._current_port = int(port_override or self.config.port)

        raw = socket.create_connection(
            (self._current_host, self._current_port),
            timeout=float(self.config.socket_timeout_s),
        )
        self._configure_socket(raw)

        if self.config.use_tls:
            ctx = ssl.create_default_context()
            raw = ctx.wrap_socket(raw, server_hostname=self._current_host)

        raw.settimeout(None)
        self._sock = raw
        self._alive = True
        self._last_recv_at = time.time()

        self._reader_thread = threading.Thread(
            target=self._reader_loop,
            name="BtcStratumReader",
            daemon=True,
        )
        self._reader_thread.start()

        self.on_status("connecting")
        self.on_log(
            f"[stratum] connected host={self._current_host} port={self._current_port} tls={self.config.use_tls}"
        )

        try:
            # Some servers return True here, some do not support it at all.
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

        sock = self._sock
        self._sock = None

        try:
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    sock.close()
                except Exception:
                    pass
        except Exception:
            pass

        if self._reader_thread is not None and threading.current_thread() is not self._reader_thread:
            try:
                self._reader_thread.join(timeout=2.0)
            except Exception:
                pass

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

    def _configure_socket(self, raw: socket.socket) -> None:
        try:
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass

        if not bool(self.config.tcp_keepalive):
            return

        try:
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except Exception:
            pass

        if hasattr(socket, "SIO_KEEPALIVE_VALS"):
            try:
                raw.ioctl(
                    socket.SIO_KEEPALIVE_VALS,
                    (
                        1,
                        int(self.config.tcp_keepidle_s * 1000),
                        int(self.config.tcp_keepintvl_s * 1000),
                    ),
                )
            except Exception:
                pass
            return

        for name, value in (
            ("TCP_KEEPIDLE", int(self.config.tcp_keepidle_s)),
            ("TCP_KEEPINTVL", int(self.config.tcp_keepintvl_s)),
            ("TCP_KEEPCNT", int(self.config.tcp_keepcnt)),
        ):
            try:
                opt = getattr(socket, name)
                raw.setsockopt(socket.IPPROTO_TCP, opt, value)
            except Exception:
                pass

    def _handle_subscribe_result(self, msg: dict) -> None:
        result = msg.get("result")

        if isinstance(result, bool):
            raise RuntimeError(
                "This server did not return a Bitcoin Stratum subscribe tuple. "
                "It is likely not a Bitcoin Stratum v1 pool for this client."
            )

        if not isinstance(result, list) or len(result) < 3:
            raise RuntimeError(f"unexpected subscribe result: {msg!r}")

        extranonce1 = str(result[1] or "")
        extranonce2_size = int(result[2])

        self.session.extranonce1_hex = extranonce1
        self.session.extranonce2_size = extranonce2_size
        self.session.subscribed = True
        self.on_session_update("subscribe")

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
        sock = self._sock
        if sock is None:
            raise RuntimeError("socket is not connected")
        with self._send_lock:
            sock.sendall(raw)

    def _send_result(self, msg_id, result=None, error=None) -> None:
        if msg_id is None:
            return
        try:
            self._send_json({"id": msg_id, "result": result, "error": error})
        except Exception:
            pass

    def _schedule_reconnect(self, host: Optional[str], port: Optional[int], wait_s: float, reason: str) -> None:
        target_host = (host or self._current_host or self.config.host).strip()
        target_port = int(port or self._current_port or self.config.port)
        self._requested_reconnect = (target_host, target_port, max(0.0, float(wait_s)))
        self._closing_for_reconnect = True
        self._alive = False
        self._fatal_error = reason

        sock = self._sock
        self._sock = None

        try:
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    sock.close()
                except Exception:
                    pass
        except Exception:
            pass

    def _reader_loop(self) -> None:
        while not self._stop.is_set():
            try:
                sock = self._sock
                if sock is None:
                    break

                chunk = sock.recv(4096)
                if not chunk:
                    self._alive = False
                    if not self._stop.is_set() and not self._closing_for_reconnect:
                        self.on_status("disconnected")
                    break

                self._last_recv_at = time.time()
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

            except OSError as exc:
                self._alive = False
                if self._stop.is_set() or self._closing_for_reconnect:
                    break
                if getattr(exc, "winerror", None) == 10038:
                    break
                self._fatal_error = str(exc)
                self.on_log(f"[stratum] reader error: {exc}")
                self.on_status("error")
                break
            except Exception as exc:
                self._alive = False
                if self._stop.is_set() or self._closing_for_reconnect:
                    break
                self._fatal_error = str(exc)
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

        if method == "client.get_version":
            self._send_result(msg.get("id"), self.config.agent, None)
            return

        if method == "client.show_message":
            text = str(params[0] or "") if params else ""
            self.on_log(f"[stratum] server-message {text}")
            return

        if method == "client.reconnect":
            host = str(params[0]).strip() if len(params) >= 1 and params[0] else self._current_host
            port = int(params[1]) if len(params) >= 2 and params[1] else self._current_port
            wait_s = float(params[2]) if len(params) >= 3 and params[2] is not None else 0.0
            self.on_log(f"[stratum] server requested reconnect host={host} port={port} wait={wait_s}")
            self._schedule_reconnect(host, port, wait_s, "server requested reconnect")
            return

        if method == "mining.set_difficulty":
            if params:
                self._share_difficulty = float(params[0])
                self.on_session_update("difficulty")
                self.on_log(f"[stratum] set_difficulty={self._share_difficulty}")
            return

        if method == "mining.set_extranonce":
            if len(params) >= 2:
                self.session.extranonce1_hex = str(params[0] or "")
                self.session.extranonce2_size = int(params[1])
                self.on_session_update("extranonce")
                self.on_log(
                    f"[stratum] set_extranonce extranonce1={self.session.extranonce1_hex} "
                    f"extranonce2_size={self.session.extranonce2_size}"
                )
            return

        if method == "mining.set_version_mask":
            if params:
                self.session.version_mask = str(params[0] or "")
                self.on_log(f"[stratum] set_version_mask params={params!r}")
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