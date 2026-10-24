from __future__ import annotations

import base64
import binascii
import json
from typing import Any


class DecodeError(ValueError):
    """A WebAuthn value could not be decoded safely."""


def b64url_decode(value: Any, *, field: str, max_bytes: int = 1_048_576) -> bytes:
    if not isinstance(value, str) or not value:
        raise DecodeError(f"{field} must be a non-empty base64url string")
    if len(value) > max_bytes * 2:
        raise DecodeError(f"{field} exceeds the encoded size limit")
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise DecodeError(f"{field} is not ASCII base64url") from exc
    if any(
        ch not in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=" for ch in raw
    ):
        raise DecodeError(f"{field} contains non-base64url characters")
    raw = raw.rstrip(b"=")
    try:
        decoded = base64.b64decode(raw + b"=" * (-len(raw) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DecodeError(f"{field} is invalid base64url") from exc
    if len(decoded) > max_bytes:
        raise DecodeError(f"{field} exceeds the decoded size limit")
    return decoded


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def json_from_b64url(value: Any, *, field: str) -> dict[str, Any]:
    raw = b64url_decode(value, field=field)
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError(f"{field} is not valid UTF-8 JSON") from exc
    if not isinstance(decoded, dict):
        raise DecodeError(f"{field} JSON must be an object")
    return decoded


def safe_summary(value: bytes) -> dict[str, Any]:
    import hashlib

    return {"length": len(value), "sha256": hashlib.sha256(value).hexdigest()}
