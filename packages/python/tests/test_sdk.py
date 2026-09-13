"""Python SDK conformance tests: canonicalization, framing, hosted stubs."""

import struct

import pytest

from trellis_sdk import (
    canonical_bytes,
    parse_strict,
    FleetConsole,
    CloudControl,
    HostedAttestation,
    HostedUnsupportedError,
)
from trellis_sdk.canon import CanonError
from trellis_sdk.client import _rpc, request_id


def test_canonical_sorted_keys():
    assert canonical_bytes({"b": 2, "a": "1"}) == b'{"a":"1","b":2}'


def test_canonical_no_unicode_normalization():
    assert canonical_bytes({"x": "é"}) != canonical_bytes({"x": "é"})


def test_duplicate_key_rejected():
    with pytest.raises(CanonError):
        parse_strict(b'{"v":1,"v":1}')


def test_negative_and_float_rejected():
    with pytest.raises(CanonError):
        parse_strict(b'{"x":-0}')
    with pytest.raises(CanonError):
        parse_strict(b'{"x":1.5}')


def test_leading_zero_rejected():
    with pytest.raises(CanonError):
        parse_strict(b'{"x":00}')


def test_request_id_format():
    rid = request_id()
    assert rid.startswith("trq_")
    assert len(rid) == 25


def test_wire_frame_roundtrip():
    import socket

    a, b = socket.socketpair()
    try:
        resp = {"v": 1, "id": "x", "ok": True, "result": {"pong": True}}
        payload = canonical_bytes(resp)
        # feed a canned response, then drive _rpc on the other end
        b.sendall(struct.pack(">I", len(payload)) + payload)
        # _rpc writes the request first; socketpair delivers it to b's buffer
        import threading

        t = threading.Thread(target=lambda: _rpc(a, "host.get", {}, "trq_" + "0" * 21))
        t.start()
        t.join(5)
        # b received the request frame; drain it
        b.recv(4096)
    finally:
        a.close()
        b.close()


def test_hosted_surfaces_not_implemented():
    with pytest.raises(HostedUnsupportedError):
        FleetConsole().enroll()
    with pytest.raises(HostedUnsupportedError):
        FleetConsole().remote_kill("trr_x")
    with pytest.raises(HostedUnsupportedError):
        CloudControl().sync()
    with pytest.raises(HostedUnsupportedError):
        HostedAttestation().anchor({"seq": "1", "hash": "0" * 64})
    try:
        FleetConsole().enroll()
    except HostedUnsupportedError as e:
        assert "TRELLIS_SPEC" in str(e)
