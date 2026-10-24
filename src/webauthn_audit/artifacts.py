from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .cbor import CBORError, decode_one
from .codec import DecodeError, b64url_decode, json_from_b64url


class ArtifactError(ValueError):
    pass


@dataclass(frozen=True)
class AuthenticatorData:
    raw_length: int
    rp_id_hash: bytes
    flags: int
    sign_count: int
    aaguid: bytes | None = None
    credential_id: bytes | None = None
    credential_public_key: dict[Any, Any] | None = None
    extensions: dict[Any, Any] | None = None

    @property
    def up(self) -> bool:
        return bool(self.flags & 0x01)

    @property
    def uv(self) -> bool:
        return bool(self.flags & 0x04)

    @property
    def be(self) -> bool:
        return bool(self.flags & 0x08)

    @property
    def bs(self) -> bool:
        return bool(self.flags & 0x10)

    @property
    def at(self) -> bool:
        return bool(self.flags & 0x40)

    @property
    def ed(self) -> bool:
        return bool(self.flags & 0x80)


def load_json(path: Path, *, max_bytes: int = 2_097_152) -> Any:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ArtifactError(f"cannot stat {path}: {exc}") from exc
    if size > max_bytes:
        raise ArtifactError(f"{path} exceeds {max_bytes} bytes")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactError(f"cannot load JSON from {path}: {exc}") from exc


def unwrap_options(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    candidate = value.get("publicKey", value)
    if not isinstance(candidate, dict):
        return None
    if "challenge" in candidate:
        return candidate
    return None


def response_kind(value: Any) -> str | None:
    if not isinstance(value, dict) or not isinstance(value.get("response"), dict):
        return None
    response = value["response"]
    if "attestationObject" in response:
        return "registration"
    if "authenticatorData" in response and "signature" in response:
        return "authentication"
    return None


def parse_client_data(response: dict[str, Any]) -> dict[str, Any]:
    body = response.get("response")
    if not isinstance(body, dict):
        raise DecodeError("response must be an object")
    return json_from_b64url(body.get("clientDataJSON"), field="response.clientDataJSON")


def parse_attestation_object(response: dict[str, Any]) -> tuple[str, dict[Any, Any], bytes]:
    body = response.get("response")
    if not isinstance(body, dict):
        raise DecodeError("response must be an object")
    raw = b64url_decode(body.get("attestationObject"), field="response.attestationObject")
    decoded, _ = decode_one(raw)
    if not isinstance(decoded, dict):
        raise CBORError("attestation object is not a CBOR map")
    fmt, statement, auth_data = decoded.get("fmt"), decoded.get("attStmt"), decoded.get("authData")
    if (
        not isinstance(fmt, str)
        or not isinstance(statement, dict)
        or not isinstance(auth_data, bytes)
    ):
        raise CBORError("attestation object lacks fmt, attStmt, or authData")
    return fmt, statement, auth_data


def parse_authenticator_data(raw: bytes) -> AuthenticatorData:
    if len(raw) < 37:
        raise DecodeError("authenticatorData is shorter than 37 bytes")
    rp_id_hash = raw[:32]
    flags = raw[32]
    sign_count = int.from_bytes(raw[33:37], "big")
    offset = 37
    aaguid: bytes | None = None
    credential_id: bytes | None = None
    credential_key: dict[Any, Any] | None = None
    extensions: dict[Any, Any] | None = None
    if flags & 0x40:
        if len(raw) < offset + 18:
            raise DecodeError("truncated attested credential data")
        aaguid = raw[offset : offset + 16]
        credential_length = int.from_bytes(raw[offset + 16 : offset + 18], "big")
        offset += 18
        if credential_length == 0 or offset + credential_length > len(raw):
            raise DecodeError("invalid credential ID length")
        credential_id = raw[offset : offset + credential_length]
        offset += credential_length
        decoded_key, consumed = decode_one(raw[offset:], require_eof=False)
        if not isinstance(decoded_key, dict):
            raise CBORError("credentialPublicKey is not a COSE_Key map")
        credential_key = decoded_key
        offset += consumed
    if flags & 0x80:
        decoded_extensions, consumed = decode_one(raw[offset:], require_eof=False)
        if not isinstance(decoded_extensions, dict):
            raise CBORError("authenticator extensions are not a map")
        extensions = decoded_extensions
        offset += consumed
    if offset != len(raw):
        raise DecodeError("authenticatorData has trailing bytes inconsistent with flags")
    return AuthenticatorData(
        raw_length=len(raw),
        rp_id_hash=rp_id_hash,
        flags=flags,
        sign_count=sign_count,
        aaguid=aaguid,
        credential_id=credential_id,
        credential_public_key=credential_key,
        extensions=extensions,
    )


def extract_authenticator_data(
    response: dict[str, Any], kind: str
) -> tuple[AuthenticatorData, str | None, dict[Any, Any] | None]:
    if kind == "registration":
        fmt, statement, raw = parse_attestation_object(response)
        return parse_authenticator_data(raw), fmt, statement
    body = response.get("response")
    if not isinstance(body, dict):
        raise DecodeError("response must be an object")
    raw = b64url_decode(body.get("authenticatorData"), field="response.authenticatorData")
    return parse_authenticator_data(raw), None, None


def origin_host(origin: str) -> tuple[str, str] | None:
    try:
        parsed = urlsplit(origin)
        if not parsed.scheme or not parsed.hostname or parsed.username or parsed.password:
            return None
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            return None
        return parsed.scheme.lower(), parsed.hostname.rstrip(".").lower()
    except ValueError:
        return None


def rp_id_matches_origin(rp_id: str, origin: str) -> bool:
    parsed = origin_host(origin)
    if parsed is None:
        return False
    _, host = parsed
    rp = rp_id.rstrip(".").lower()
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        return host == rp or host.endswith("." + rp)


def rp_hash(rp_id: str) -> bytes:
    return hashlib.sha256(rp_id.encode("utf-8")).digest()


def envelope_parts(
    value: Any,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any]]:
    if not isinstance(value, dict):
        return None, None, {}
    expected = value.get("expected", {})
    if not isinstance(expected, dict):
        expected = {}
    for key in ("creationOptions", "requestOptions", "options"):
        if key in value:
            options = unwrap_options(value[key])
            credential = value.get("credential")
            return options, credential if isinstance(credential, dict) else None, expected
    if response_kind(value):
        return None, value, expected
    options = unwrap_options(value)
    return options, None, expected
