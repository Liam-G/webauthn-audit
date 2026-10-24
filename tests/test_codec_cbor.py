from __future__ import annotations

import pytest

from webauthn_audit.cbor import CBORError, decode_one
from webauthn_audit.codec import DecodeError, b64url_decode, b64url_encode, json_from_b64url

from .helpers import b64, cbor


def test_base64url_round_trip_and_json() -> None:
    raw = b"hello\x00world"
    assert b64url_decode(b64url_encode(raw), field="x") == raw
    assert json_from_b64url(b64(b'{"ok":true}'), field="x") == {"ok": True}


@pytest.mark.parametrize("value", ["***", "é", "a", ""])
def test_base64url_rejects_invalid_values(value: str) -> None:
    with pytest.raises(DecodeError):
        b64url_decode(value, field="x")


def test_cbor_nested_values_and_consumed_length() -> None:
    value = {1: -7, "bytes": b"abc", "array": [True, None, 42]}
    encoded = cbor(value)
    assert decode_one(encoded) == (value, len(encoded))


def test_cbor_rejects_truncation_duplicates_and_trailing_bytes() -> None:
    for value in (b"\x58", b"\xa2\x01\x01\x01\x02", cbor({1: 2}) + b"x"):
        with pytest.raises(CBORError):
            decode_one(value)
