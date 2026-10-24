from __future__ import annotations

import base64
import hashlib
import json
from typing import Any


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def cbor(value: Any) -> bytes:
    if isinstance(value, bool):
        return bytes([0xF5 if value else 0xF4])
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        if value >= 0:
            return _head(0, value)
        return _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode()
        return _head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(cbor(item) for item in value)
    if isinstance(value, dict):
        return _head(5, len(value)) + b"".join(cbor(k) + cbor(v) for k, v in value.items())
    raise TypeError(type(value))


def _head(major: int, value: int) -> bytes:
    prefix = major << 5
    if value < 24:
        return bytes([prefix | value])
    if value < 256:
        return bytes([prefix | 24, value])
    if value < 65536:
        return bytes([prefix | 25]) + value.to_bytes(2, "big")
    return bytes([prefix | 26]) + value.to_bytes(4, "big")


RP_ID = "login.example.test"
ORIGIN = "https://login.example.test"
CHALLENGE = bytes(range(32))
CREDENTIAL_ID = bytes(range(32, 64))
USER_HANDLE = bytes(range(64, 80))
COSE_ES256 = {1: 2, 3: -7, -1: 1, -2: b"x" * 32, -3: b"y" * 32}


def registration_envelope() -> dict[str, Any]:
    options = {
        "challenge": b64(CHALLENGE),
        "rp": {"id": RP_ID, "name": "Example"},
        "user": {"id": b64(USER_HANDLE), "name": "liam", "displayName": "Liam"},
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},
            {"type": "public-key", "alg": -257},
        ],
        "timeout": 300_000,
        "excludeCredentials": [],
        "authenticatorSelection": {
            "residentKey": "required",
            "requireResidentKey": True,
            "userVerification": "required",
        },
        "attestation": "none",
        "extensions": {"credProps": True},
    }
    client_data = json.dumps(
        {
            "type": "webauthn.create",
            "challenge": b64(CHALLENGE),
            "origin": ORIGIN,
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode()
    auth_data = (
        hashlib.sha256(RP_ID.encode()).digest()
        + bytes([0x5D])
        + (0).to_bytes(4, "big")
        + bytes(16)
        + len(CREDENTIAL_ID).to_bytes(2, "big")
        + CREDENTIAL_ID
        + cbor(COSE_ES256)
    )
    attestation = cbor({"fmt": "none", "attStmt": {}, "authData": auth_data})
    credential = {
        "id": b64(CREDENTIAL_ID),
        "rawId": b64(CREDENTIAL_ID),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64(client_data),
            "attestationObject": b64(attestation),
            "transports": ["internal", "hybrid"],
        },
        "clientExtensionResults": {"credProps": {"rk": True}},
    }
    return {
        "creationOptions": {"publicKey": options},
        "credential": credential,
        "expected": {"rpId": RP_ID, "origins": [ORIGIN], "requireUserVerification": True},
    }


def authentication_envelope() -> dict[str, Any]:
    options = {
        "challenge": b64(CHALLENGE),
        "rpId": RP_ID,
        "timeout": 300_000,
        "allowCredentials": [
            {"type": "public-key", "id": b64(CREDENTIAL_ID), "transports": ["internal"]}
        ],
        "userVerification": "required",
    }
    client_data = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": b64(CHALLENGE),
            "origin": ORIGIN,
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode()
    auth_data = hashlib.sha256(RP_ID.encode()).digest() + bytes([0x1D]) + (8).to_bytes(4, "big")
    credential = {
        "id": b64(CREDENTIAL_ID),
        "rawId": b64(CREDENTIAL_ID),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64(client_data),
            "authenticatorData": b64(auth_data),
            "signature": b64(b"s" * 64),
            "userHandle": b64(USER_HANDLE),
        },
        "clientExtensionResults": {},
    }
    return {
        "requestOptions": {"publicKey": options},
        "credential": credential,
        "expected": {
            "rpId": RP_ID,
            "origins": [ORIGIN],
            "previousSignCount": 7,
            "backupEligible": True,
            "userHandle": b64(USER_HANDLE),
            "requireUserVerification": True,
        },
    }
