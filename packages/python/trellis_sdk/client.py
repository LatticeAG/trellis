"""Control-socket client + agent heartbeat channel."""

from __future__ import annotations

import os
import socket
import struct
import time

from .canon import canonical_bytes, parse_strict, Json

REQ_MAX = 65536
RESP_MAX = 1048576
DEFAULT_SOCKET = "/run/trellis/control.sock"


class TrellisError(Exception):
    def __init__(self, code: str, msg: str | None = None):
        super().__init__(msg or code)
        self.code = code


_counter = 0


def request_id() -> str:
    global _counter
    _counter += 1
    t = format(int(time.time() * 1000), "x")[-10:]
    c = format(_counter, "x")[-11:]
    return "trq_" + (t + c).rjust(21, "0")


def _rpc(sock: socket.socket, method: str, params: Json, req_id: str | None = None) -> Json:
    req = {"v": 1, "id": req_id or request_id(), "method": method, "params": params}
    payload = canonical_bytes(req)
    if len(payload) > REQ_MAX:
        raise TrellisError("OUTPUT_LIMIT")
    sock.sendall(struct.pack(">I", len(payload)) + payload)
    hdr = _recv_exact(sock, 4)
    (n,) = struct.unpack(">I", hdr)
    if n > RESP_MAX:
        raise TrellisError("OUTPUT_LIMIT", "response frame over bound")
    body = _recv_exact(sock, n)
    resp = parse_strict(body)
    if resp.get("ok") is True:
        return resp["result"]
    err = resp.get("error") or {}
    raise TrellisError(err.get("code", "INVALID_INPUT"))


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    out = b""
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise TrellisError("UNAUTHORIZED", "control socket closed")
        out += chunk
    return out


class Client:
    """Daemon control client. One framed request per connection; the run is
    daemon-owned — disconnecting never stops it."""

    def __init__(self, socket_path: str = DEFAULT_SOCKET):
        self.socket_path = socket_path

    def call(self, method: str, params: Json) -> Json:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.connect(self.socket_path)
                return _rpc(s, method, params)
        except OSError as e:
            raise TrellisError("UNAUTHORIZED", f"control socket unavailable: {e}")

    def host_get(self) -> Json:
        return self.call("host.get", {})

    def run_get(self, run_id: str) -> Json:
        return self.call("run.get", {"run_id": run_id})

    def run_list(self, limit: int = 32, after: str | None = None) -> Json:
        # `after` is a required field; the wire value for "from start" is null.
        return self.call("run.list", {"after": after, "limit": limit})

    def run_start(self, params: Json) -> Json:
        return self.call("run.start", params)

    def run_stop(self, run_id: str, reason: str = "OPERATOR", note_hash: str | None = None) -> Json:
        return self.call("run.stop", {"run_id": run_id, "reason": reason, "note_hash": note_hash})

    def inventory_get(self, run_id: str) -> Json:
        return self.call("inventory.get", {"run_id": run_id})

    def events_read(self, run_id: str, after_seq: str, through: Json, limit: int = 256) -> Json:
        return self.call(
            "events.read",
            {"run_id": run_id, "after_seq": after_seq, "through": through, "limit": limit},
        )

    def certificate_get(self, run_id: str) -> Json:
        return self.call("certificate.get", {"run_id": run_id})


class HeartbeatChannel:
    """Agent-side fd-3 channel. Retains request IDs across uncertain retries,
    never remints a consumed challenge, and never spins a hidden heartbeat
    once closed or failed.
    """

    def __init__(self, fd: int = 3):
        self._sock = socket.socket(fileno=fd)
        self._outstanding: Json | None = None
        self._closed = False

    @classmethod
    def connect(cls, socket_path: str) -> "HeartbeatChannel":
        obj = cls.__new__(cls)
        obj._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        obj._sock.connect(socket_path)
        obj._outstanding = None
        obj._closed = False
        return obj

    def challenge(self) -> Json:
        r = _rpc(self._sock, "agent.challenge", {})
        self._outstanding = r
        return r

    def beat(
        self,
        *,
        run_id: str,
        boot_id: str,
        scope_ok: bool,
        claimed_processes: int,
        progress: str,
        request_id: str | None = None,
    ) -> Json:
        if self._closed:
            raise TrellisError("STOPPED", "channel closed")
        ch = self._outstanding
        if ch is None:
            raise TrellisError("CHALLENGE_INVALID", "no outstanding challenge")
        params = {
            "run_id": run_id,
            "boot_id": boot_id,
            "challenge_id": ch["challenge_id"],
            "seq": ch["seq"],
            "nonce": ch["nonce"],
            "policy_hash": ch["policy_hash"],
            "scope_ok": scope_ok,
            "claimed_processes": claimed_processes,
            "progress": progress,
        }
        try:
            r = _rpc(self._sock, "agent.beat", params, request_id)
        except TrellisError as e:
            if e.code in ("STOPPED", "CHALLENGE_INVALID"):
                self._closed = True
            raise
        self._outstanding = r.get("next")
        return r

    def close(self) -> None:
        self._closed = True
        self._sock.close()


def ctl(*args: str) -> tuple[int, str]:
    """Invoke trellis-ctl; Rust owns every verification/crypto decision."""
    import subprocess

    exe = os.environ.get("TRELLIS_CTL", "trellis-ctl")
    r = subprocess.run([exe, *args], capture_output=True, text=True)
    return r.returncode, r.stdout


def verify_bundle(
    path: str,
    *,
    log_pins: list[str],
    policy_pins: list[str],
    head: str | None = None,
    allow_prefix: bool = False,
) -> Json:
    """Offline evidence verification via trellis-ctl. Raises TrellisError on
    failure with the protocol Code."""
    args = ["verify", "--input", path]
    for p in log_pins:
        args += ["--log-pin", p]
    for p in policy_pins:
        args += ["--policy-pin", p]
    if head:
        args += ["--head", head]
    if allow_prefix:
        args.append("--allow-prefix")
    code, out = ctl(*args)
    parsed = parse_strict(out.strip().encode()) if out.strip() else {}
    if code == 0:
        return parsed
    err = (parsed.get("error") or {}).get("code", "INVALID_INPUT")
    raise TrellisError(err)
