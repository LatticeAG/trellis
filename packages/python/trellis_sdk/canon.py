"""Canonical wire JSON: the byte-exact subset trellis-core produces.

Only safe nonnegative integers, strings, booleans, null, arrays, and objects
with unique keys are permitted. Canonical form sorts object keys by code
point, uses no whitespace, and escapes per the wire profile.
"""

from __future__ import annotations

import json

Json = object  # dict | list | str | int | bool | None

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}

MAX_SAFE_INT = 9007199254740991


class CanonError(ValueError):
    pass


def _esc(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _check(v: Json) -> None:
    if isinstance(v, bool) or v is None or isinstance(v, str):
        return
    if isinstance(v, int):
        if v < 0 or v > MAX_SAFE_INT:
            raise CanonError("number is not a safe nonnegative integer")
        return
    if isinstance(v, list):
        for x in v:
            _check(x)
        return
    if isinstance(v, dict):
        for k, x in v.items():
            if not isinstance(k, str):
                raise CanonError("object key is not a string")
            _check(x)
        return
    raise CanonError(f"unsupported wire type {type(v).__name__}")


def canonical_bytes(v: Json) -> bytes:
    """Serialize to canonical wire bytes (UTF-8, no normalization)."""
    _check(v)
    # json.dumps with sort_keys uses code-point order for str keys; ensure
    # separators produce no whitespace; ensure_ascii=False keeps unicode raw.
    return json.dumps(
        v, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _reject_dupes(pairs: list) -> dict:
    out: dict = {}
    for k, v in pairs:
        if k in out:
            raise CanonError(f"duplicate key {k!r}")
        out[k] = v
    return out


def parse_strict(data: bytes | str) -> Json:
    """Strict wire parse: duplicate keys and unsafe numbers rejected."""
    try:
        v = json.loads(data, object_pairs_hook=_reject_dupes, parse_int=_strict_int,
                       parse_float=_bad_number, parse_constant=_bad_constant)
    except CanonError:
        raise
    except json.JSONDecodeError as e:
        raise CanonError(str(e)) from e
    _check(v)
    return v


def _strict_int(s: str) -> int:
    n = int(s)
    if s.startswith("-") or n < 0 or n > MAX_SAFE_INT or (len(s) > 1 and s[0] == "0"):
        raise CanonError("number is not a safe nonnegative integer")
    return n


def _bad_number(s: str):
    raise CanonError(f"non-integer number {s!r} on the wire")


def _bad_constant(s: str):
    raise CanonError(f"non-wire literal {s!r}")
