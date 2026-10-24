from __future__ import annotations

import hmac
import re
from pathlib import Path
from typing import Any

from .artifacts import (
    AuthenticatorData,
    envelope_parts,
    extract_authenticator_data,
    origin_host,
    response_kind,
    rp_hash,
    rp_id_matches_origin,
)
from .catalog import RULES
from .cbor import CBORError
from .codec import DecodeError, b64url_decode, safe_summary
from .models import AuditResult, Finding, Location, Policy

VALID_TRANSPORTS = {"usb", "nfc", "ble", "smart-card", "hybrid", "internal"}
VALID_HINTS = {"security-key", "client-device", "hybrid"}
ATTESTATION_FIELDS = {
    "none": frozenset(),
    "packed": frozenset({"alg", "sig"}),
    "tpm": frozenset({"ver", "alg", "x5c", "sig", "certInfo", "pubArea"}),
    "android-key": frozenset({"alg", "sig", "x5c"}),
    "android-safetynet": frozenset({"ver", "response"}),
    "fido-u2f": frozenset({"sig", "x5c"}),
    "apple": frozenset({"x5c"}),
    "compound": frozenset(),
}
KNOWN_EXTENSIONS = {
    "appid",
    "appidExclude",
    "credProps",
    "credProtect",
    "hmacCreateSecret",
    "hmacGetSecret",
    "largeBlob",
    "minPinLength",
    "prf",
    "txAuthSimple",
    "uvm",
    "devicePubKey",
    "payment",
    "thirdPartyPayment",
    "supplementalPubKeys",
}
PII_USER_HANDLE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$|^[+]?[0-9][0-9 .()/-]{6,}$")


class Auditor:
    def __init__(self, policy: Policy):
        self.policy = policy
        self.result = AuditResult()
        self.artifact = "<memory>"

    def audit(self, value: Any, artifact: str = "<memory>") -> AuditResult:
        self.artifact = artifact
        self.result.artifacts.append(artifact)
        options, credential, expected = envelope_parts(value)
        if options is None and credential is None:
            self._emit(
                "WAC-030",
                "Artifact is not a recognized WebAuthn options, credential, or envelope",
                "",
            )
            return self.result

        kind = response_kind(credential) if credential else None
        option_kind = self._option_kind(options) if options else None
        if options:
            self._audit_options(options, option_kind or "authentication", expected)
        if credential:
            if kind is None:
                self._emit(
                    "WAC-030",
                    "Credential object has no recognized authenticator response",
                    "/credential",
                )
            else:
                self._audit_credential(credential, kind, options, expected)
        return self.result

    @staticmethod
    def _option_kind(options: dict[str, Any] | None) -> str | None:
        if options is None:
            return None
        return (
            "registration"
            if "rp" in options or "user" in options or "pubKeyCredParams" in options
            else "authentication"
        )

    def _emit(self, rule_id: str, message: str, pointer: str, **evidence: Any) -> None:
        self.result.findings.append(
            Finding(RULES[rule_id], message, Location(self.artifact, pointer), evidence)
        )

    def _decode(
        self, value: Any, field: str, pointer: str, *, required: bool = True
    ) -> bytes | None:
        if value is None and not required:
            return None
        try:
            return b64url_decode(value, field=field)
        except DecodeError as exc:
            self._emit("WAC-001", str(exc), pointer)
            return None

    def _audit_options(self, options: dict[str, Any], kind: str, expected: dict[str, Any]) -> None:
        challenge = self._decode(options.get("challenge"), "challenge", "/options/challenge")
        if challenge is not None and len(challenge) < 16:
            self._emit(
                "WAC-002",
                f"Challenge is {len(challenge)} bytes; at least 16 are recommended",
                "/options/challenge",
                length=len(challenge),
            )
        timeout = options.get("timeout")
        if timeout is not None and (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or timeout < 300_000
            or timeout > 600_000
        ):
            self._emit(
                "WAC-039",
                f"Ceremony timeout {timeout!r} is outside 300000–600000 ms",
                "/options/timeout",
                timeout=timeout,
            )
        rp_id = self._effective_rp_id(options, expected)
        origins = self._origins(expected)
        if rp_id:
            for origin in origins:
                related_validated = (
                    self.policy.allow_related_origins
                    or expected.get("relatedOriginsValidated") is True
                )
                if not related_validated and not rp_id_matches_origin(rp_id, origin):
                    self._emit(
                        "WAC-008",
                        f"RP ID {rp_id!r} is incompatible with origin {origin!r}",
                        "/options/rpId" if kind == "authentication" else "/options/rp/id",
                        rp_id=rp_id,
                        origin=origin,
                    )
        for origin in origins:
            parsed = origin_host(origin)
            if parsed is None:
                self._emit(
                    "WAC-005",
                    f"Configured origin {origin!r} is not a serialized origin",
                    "/expected/origins",
                )
            elif parsed[0] != "https" and not (parsed[0] == "http" and parsed[1] == "localhost"):
                self._emit(
                    "WAC-009",
                    f"Origin {origin!r} does not use HTTPS",
                    "/expected/origins",
                    origin=origin,
                )

        self._audit_descriptors(
            options.get("excludeCredentials")
            if kind == "registration"
            else options.get("allowCredentials"),
            "/options/excludeCredentials"
            if kind == "registration"
            else "/options/allowCredentials",
        )
        self._audit_hints(options.get("hints"), "/options/hints")
        extensions = options.get("extensions")
        if extensions is not None and not isinstance(extensions, dict):
            self._emit("WAC-031", "extensions must be an object", "/options/extensions")

        uv = (
            options.get("authenticatorSelection", {}).get("userVerification")
            if kind == "registration"
            else options.get("userVerification")
        )
        if not isinstance(uv, str):
            uv = "preferred"
        if self.policy.require_user_verification and uv != "required":
            self._emit(
                "WAC-012",
                f"Profile {self.policy.profile!r} requires UV, but options use {uv!r}",
                "/options/userVerification",
                configured=uv,
            )
        if kind == "registration":
            self._audit_registration_options(options)

    def _audit_registration_options(self, options: dict[str, Any]) -> None:
        user = options.get("user")
        if not isinstance(user, dict):
            self._emit("WAC-030", "Registration options lack a user object", "/options/user")
        else:
            handle = self._decode(user.get("id"), "user.id", "/options/user/id")
            if handle is not None:
                if not 1 <= len(handle) <= 64:
                    self._emit(
                        "WAC-019",
                        f"User handle is {len(handle)} bytes",
                        "/options/user/id",
                        length=len(handle),
                    )
                try:
                    rendered = handle.decode("utf-8")
                except UnicodeDecodeError:
                    rendered = ""
                if rendered and PII_USER_HANDLE.search(rendered):
                    self._emit(
                        "WAC-020",
                        "User handle resembles a human-readable identifier",
                        "/options/user/id",
                        value_summary=safe_summary(handle),
                    )

        params = options.get("pubKeyCredParams")
        offered: list[int] = []
        malformed = False
        if isinstance(params, list):
            seen: set[int] = set()
            for index, entry in enumerate(params):
                if (
                    not isinstance(entry, dict)
                    or entry.get("type") != "public-key"
                    or not isinstance(entry.get("alg"), int)
                ):
                    malformed = True
                    continue
                alg = entry["alg"]
                if alg in seen:
                    malformed = True
                seen.add(alg)
                offered.append(alg)
                if alg == -65535:
                    self._emit(
                        "WAC-023",
                        "COSE algorithm -65535 (RS1) is offered",
                        f"/options/pubKeyCredParams/{index}/alg",
                        algorithm=alg,
                    )
        else:
            malformed = True
        if malformed:
            self._emit(
                "WAC-022",
                "pubKeyCredParams contains malformed or duplicate entries",
                "/options/pubKeyCredParams",
            )
        if not set(offered).intersection(self.policy.allowed_algorithms):
            self._emit(
                "WAC-021",
                "No offered algorithm is allowed by policy",
                "/options/pubKeyCredParams",
                offered=offered,
                allowed=list(self.policy.allowed_algorithms),
            )

        selection = options.get("authenticatorSelection")
        if not isinstance(selection, dict):
            selection = {}
        resident = selection.get("residentKey", "discouraged")
        legacy = selection.get("requireResidentKey")
        if self.policy.require_discoverable_credentials and resident != "required":
            self._emit(
                "WAC-024",
                f"Passkey profile requires residentKey=required; found {resident!r}",
                "/options/authenticatorSelection/residentKey",
            )
        if (legacy is True and resident in ("discouraged", "preferred")) or (
            legacy is False and resident == "required"
        ):
            self._emit(
                "WAC-025",
                "requireResidentKey contradicts residentKey",
                "/options/authenticatorSelection",
            )
        attestation = options.get("attestation", "none")
        if attestation in ("indirect", "direct", "enterprise"):
            self._emit(
                "WAC-026",
                f"Registration requests {attestation!r} attestation",
                "/options/attestation",
                attestation=attestation,
            )

    def _audit_descriptors(self, descriptors: Any, pointer: str) -> None:
        if descriptors is None:
            return
        if not isinstance(descriptors, list):
            self._emit("WAC-028", "Credential descriptors must be an array", pointer)
            return
        seen: set[bytes] = set()
        for index, descriptor in enumerate(descriptors):
            item_pointer = f"{pointer}/{index}"
            if not isinstance(descriptor, dict) or descriptor.get("type") != "public-key":
                self._emit("WAC-028", "Credential descriptor type must be public-key", item_pointer)
                continue
            credential_id = self._decode(
                descriptor.get("id"), "credential descriptor id", item_pointer + "/id"
            )
            if credential_id is not None:
                if credential_id in seen or len(credential_id) < 16:
                    self._emit(
                        "WAC-028",
                        "Credential descriptor ID is duplicate or shorter than 16 bytes",
                        item_pointer + "/id",
                        length=len(credential_id),
                    )
                seen.add(credential_id)
            transports = descriptor.get("transports", [])
            if not isinstance(transports, list) or any(
                t not in VALID_TRANSPORTS for t in transports
            ):
                self._emit(
                    "WAC-040",
                    "Credential descriptor contains an unknown transport",
                    item_pointer + "/transports",
                )

    def _audit_hints(self, hints: Any, pointer: str) -> None:
        if hints is None:
            return
        if not isinstance(hints, list) or any(hint not in VALID_HINTS for hint in hints):
            self._emit("WAC-040", "Options contain an unknown authenticator hint", pointer)

    def _audit_credential(
        self,
        credential: dict[str, Any],
        kind: str,
        options: dict[str, Any] | None,
        expected: dict[str, Any],
    ) -> None:
        base = "/credential" if options is not None else ""
        if credential.get("type") != "public-key":
            self._emit("WAC-036", "Credential type is not public-key", base + "/type")
        raw_id = self._decode(credential.get("rawId"), "credential.rawId", base + "/rawId")
        visible_id = self._decode(credential.get("id"), "credential.id", base + "/id")
        if (
            raw_id is not None
            and visible_id is not None
            and not hmac.compare_digest(raw_id, visible_id)
        ):
            self._emit("WAC-029", "credential.id and credential.rawId differ", base)
        if raw_id is not None and len(raw_id) < 16:
            self._emit(
                "WAC-033",
                f"Credential ID is only {len(raw_id)} bytes",
                base + "/rawId",
                length=len(raw_id),
            )

        body = credential.get("response")
        if not isinstance(body, dict):
            self._emit("WAC-030", "Credential response is missing", base + "/response")
            return
        if options is None:
            self._emit(
                "WAC-045",
                "Response is not paired with the server-issued ceremony options",
                base,
            )
        required = (
            ("clientDataJSON", "attestationObject")
            if kind == "registration"
            else ("clientDataJSON", "authenticatorData", "signature")
        )
        for name in required:
            if not body.get(name):
                self._emit(
                    "WAC-030",
                    f"Required response field {name} is absent",
                    base + f"/response/{name}",
                )
        if kind == "authentication":
            signature = self._decode(
                body.get("signature"), "response.signature", base + "/response/signature"
            )
            if signature is not None and len(signature) < 8:
                self._emit(
                    "WAC-030",
                    "Authentication signature is implausibly short",
                    base + "/response/signature",
                )
        if kind == "registration":
            transports = body.get("transports", [])
            if not isinstance(transports, list) or any(
                item not in VALID_TRANSPORTS for item in transports
            ):
                self._emit(
                    "WAC-040",
                    "Registration response contains an unknown transport",
                    base + "/response/transports",
                )
        attachment = credential.get("authenticatorAttachment")
        if attachment not in (None, "platform", "cross-platform"):
            self._emit(
                "WAC-040",
                f"Unknown authenticatorAttachment {attachment!r}",
                base + "/authenticatorAttachment",
            )

        try:
            from .artifacts import parse_client_data

            client_data = parse_client_data(credential)
        except DecodeError as exc:
            self._emit("WAC-001", str(exc), base + "/response/clientDataJSON")
            client_data = None
        if client_data is not None:
            self._audit_client_data(client_data, kind, options, expected, base)

        try:
            auth_data, fmt, statement = extract_authenticator_data(credential, kind)
        except (DecodeError, CBORError) as exc:
            self._emit("WAC-001", str(exc), base + "/response")
            return
        self._audit_auth_data(auth_data, kind, options, expected, base)
        if kind == "registration":
            self._audit_attestation(fmt, statement, base)
            self._audit_public_key(auth_data, raw_id, options, body, base)
        else:
            self._audit_assertion_binding(credential, raw_id, options, expected, base)
        self._audit_client_extensions(credential, options, base)

    def _audit_client_data(
        self,
        data: dict[str, Any],
        kind: str,
        options: dict[str, Any] | None,
        expected: dict[str, Any],
        base: str,
    ) -> None:
        expected_type = "webauthn.create" if kind == "registration" else "webauthn.get"
        if data.get("type") != expected_type:
            self._emit(
                "WAC-004",
                f"Expected {expected_type!r}; got {data.get('type')!r}",
                base + "/response/clientDataJSON/type",
            )
        if options is not None:
            issued = self._decode(
                options.get("challenge"), "options.challenge", "/options/challenge"
            )
            returned = self._decode(
                data.get("challenge"),
                "clientData.challenge",
                base + "/response/clientDataJSON/challenge",
            )
            if (
                issued is not None
                and returned is not None
                and not hmac.compare_digest(issued, returned)
            ):
                self._emit(
                    "WAC-003",
                    "Signed challenge differs from issued challenge",
                    base + "/response/clientDataJSON/challenge",
                )
        origin = data.get("origin")
        origins = self._origins(expected)
        if not isinstance(origin, str) or (origins and origin not in origins):
            self._emit(
                "WAC-005",
                f"Signed origin {origin!r} is not trusted",
                base + "/response/clientDataJSON/origin",
                origin=origin,
            )
        elif origin_host(origin) is None:
            self._emit(
                "WAC-005",
                f"Signed origin {origin!r} is not a valid serialized origin",
                base + "/response/clientDataJSON/origin",
                origin=origin,
            )
        else:
            parsed_origin = origin_host(origin)
            assert parsed_origin is not None
            if parsed_origin[0] != "https" and not (
                parsed_origin[0] == "http" and parsed_origin[1] == "localhost"
            ):
                self._emit(
                    "WAC-009",
                    f"Signed origin {origin!r} does not use HTTPS",
                    base + "/response/clientDataJSON/origin",
                    origin=origin,
                )
        if not origins:
            self._emit(
                "WAC-045",
                "No trusted origin allowlist was supplied for response correlation",
                base + "/response/clientDataJSON/origin",
            )
        if data.get("crossOrigin") is True and not self.policy.allow_cross_origin:
            self._emit(
                "WAC-006",
                "clientDataJSON has crossOrigin=true",
                base + "/response/clientDataJSON/crossOrigin",
            )
        top_origin = data.get("topOrigin")
        if top_origin is not None and (
            not isinstance(top_origin, str) or (origins and top_origin not in origins)
        ):
            self._emit(
                "WAC-007",
                f"Signed topOrigin {top_origin!r} is not trusted",
                base + "/response/clientDataJSON/topOrigin",
                top_origin=top_origin,
            )
        if "tokenBinding" in data:
            self._emit(
                "WAC-041",
                "clientDataJSON contains legacy tokenBinding",
                base + "/response/clientDataJSON/tokenBinding",
            )

    def _audit_auth_data(
        self,
        data: AuthenticatorData,
        kind: str,
        options: dict[str, Any] | None,
        expected: dict[str, Any],
        base: str,
    ) -> None:
        pointer = base + "/response/authenticatorData"
        rp_id = self._effective_rp_id(options, expected)
        if rp_id is None:
            self._emit(
                "WAC-045",
                "No expected RP ID was supplied for authenticator-data correlation",
                pointer,
            )
        if rp_id and not hmac.compare_digest(data.rp_id_hash, rp_hash(rp_id)):
            self._emit(
                "WAC-010",
                "Authenticator RP ID hash does not match expected RP ID",
                pointer,
                expected_rp_id=rp_id,
            )
        if not data.up:
            self._emit("WAC-011", "UP flag is clear", pointer, flags=f"0x{data.flags:02x}")
        require_uv = self.policy.require_user_verification or bool(
            expected.get("requireUserVerification")
        )
        if options:
            configured_uv = (
                options.get("authenticatorSelection", {}).get("userVerification")
                if kind == "registration"
                else options.get("userVerification")
            )
            require_uv = require_uv or configured_uv == "required"
        if require_uv and not data.uv:
            self._emit(
                "WAC-013",
                "UV was required but the UV flag is clear",
                pointer,
                flags=f"0x{data.flags:02x}",
            )
        if data.flags & 0x22:
            self._emit(
                "WAC-014",
                "Reserved authenticator flag bit is set",
                pointer,
                flags=f"0x{data.flags:02x}",
            )
        if data.bs and not data.be:
            self._emit(
                "WAC-015", "BS is set while BE is clear", pointer, flags=f"0x{data.flags:02x}"
            )
        expected_be = expected.get("backupEligible")
        if kind == "authentication" and isinstance(expected_be, bool) and data.be != expected_be:
            self._emit(
                "WAC-043",
                f"BE flag {data.be} differs from stored value {expected_be}",
                pointer,
                expected=expected_be,
                current=data.be,
            )
        if kind == "registration" and not data.at:
            self._emit("WAC-017", "Registration authenticator data has AT clear", pointer)
        if kind == "authentication" and data.at:
            self._emit("WAC-016", "Authentication authenticator data has AT set", pointer)
        previous = expected.get("previousSignCount", self.policy.previous_sign_count)
        if (
            kind == "authentication"
            and isinstance(previous, int)
            and (previous or data.sign_count)
            and data.sign_count <= previous
        ):
            self._emit(
                "WAC-018",
                f"Counter {data.sign_count} did not exceed stored value {previous}",
                pointer,
                previous=previous,
                current=data.sign_count,
            )
        if data.ed != (data.extensions is not None):
            self._emit("WAC-031", "ED flag and parsed authenticator extensions disagree", pointer)
        self.result.observations.update(
            {
                "flags": {
                    "UP": data.up,
                    "UV": data.uv,
                    "BE": data.be,
                    "BS": data.bs,
                    "AT": data.at,
                    "ED": data.ed,
                },
                "signCount": data.sign_count,
                "authenticatorDataLength": data.raw_length,
            }
        )
        if data.aaguid is not None:
            self.result.observations["aaguid"] = data.aaguid.hex()

    def _audit_attestation(
        self, fmt: str | None, statement: dict[Any, Any] | None, base: str
    ) -> None:
        if fmt is None:
            return
        self.result.observations["attestationFormat"] = fmt
        requirements = ATTESTATION_FIELDS.get(fmt)
        if requirements is None:
            self._emit(
                "WAC-027",
                f"Unknown attestation format {fmt!r}",
                base + "/response/attestationObject/fmt",
                format=fmt,
            )
        elif statement is not None:
            missing = sorted(requirements.difference(statement))
            if missing:
                self._emit(
                    "WAC-027",
                    f"Attestation format {fmt!r} lacks required fields: {', '.join(missing)}",
                    base + "/response/attestationObject/attStmt",
                    format=fmt,
                    missing=missing,
                )
        if (
            self.policy.allowed_attestation_formats
            and fmt not in self.policy.allowed_attestation_formats
        ):
            self._emit(
                "WAC-027",
                f"Attestation format {fmt!r} is not allowed",
                base + "/response/attestationObject/fmt",
                format=fmt,
            )
        if fmt == "none" and statement:
            self._emit(
                "WAC-027",
                "none attestation must have an empty attestation statement",
                base + "/response/attestationObject/attStmt",
            )
        if statement and any(key in statement for key in ("x5c", "sig", "certInfo")):
            self._emit(
                "WAC-042",
                "Artifact includes attestation evidence; reports contain summaries only",
                base + "/response/attestationObject/attStmt",
            )

    def _audit_public_key(
        self,
        data: AuthenticatorData,
        outer_id: bytes | None,
        options: dict[str, Any] | None,
        response: dict[str, Any],
        base: str,
    ) -> None:
        pointer = base + "/response/attestationObject/authData/credentialPublicKey"
        key = data.credential_public_key
        if (
            not isinstance(key, dict)
            or not isinstance(key.get(1), int)
            or not isinstance(key.get(3), int)
        ):
            self._emit("WAC-034", "COSE key lacks integer kty (1) or alg (3)", pointer)
            return
        kty, alg = key[1], key[3]
        valid = True
        if kty == 2:  # EC2
            curve_lengths = {1: 32, 2: 48, 3: 66, 8: 32}
            curve = key.get(-1)
            coordinate_length = curve_lengths.get(curve) if isinstance(curve, int) else None
            valid = (
                coordinate_length is not None
                and isinstance(key.get(-2), bytes)
                and isinstance(key.get(-3), bytes)
                and len(key[-2]) == coordinate_length
                and len(key[-3]) == coordinate_length
            )
        elif kty == 3:  # RSA
            valid = isinstance(key.get(-1), bytes) and isinstance(key.get(-2), bytes)
        elif kty == 1:  # OKP
            curve = key.get(-1)
            expected_length = {6: 32, 7: 57}.get(curve) if isinstance(curve, int) else None
            valid = (
                expected_length is not None
                and isinstance(key.get(-2), bytes)
                and len(key[-2]) == expected_length
            )
        else:
            valid = False
        if not valid:
            self._emit(
                "WAC-034",
                f"Malformed or unsupported COSE key type {kty}",
                pointer,
                key_type=kty,
                algorithm=alg,
            )
        expected_kty = {
            -7: 2,
            -35: 2,
            -36: 2,
            -47: 2,
            -51: 2,
            -52: 2,
            -257: 3,
            -258: 3,
            -259: 3,
            -37: 3,
            -38: 3,
            -39: 3,
            -8: 1,
            -53: 1,
        }.get(alg)
        if expected_kty is not None and expected_kty != kty:
            self._emit(
                "WAC-034",
                f"COSE algorithm {alg} is incompatible with key type {kty}",
                pointer,
                key_type=kty,
                algorithm=alg,
            )
        offered = []
        if options and isinstance(options.get("pubKeyCredParams"), list):
            offered = [
                item.get("alg") for item in options["pubKeyCredParams"] if isinstance(item, dict)
            ]
            if alg not in offered:
                self._emit(
                    "WAC-035",
                    f"Credential algorithm {alg} was not offered",
                    pointer,
                    algorithm=alg,
                    offered=offered,
                )
        if alg not in self.policy.allowed_algorithms:
            self._emit(
                "WAC-021",
                f"Credential algorithm {alg} is not allowed by policy",
                pointer,
                algorithm=alg,
            )
        if data.credential_id is not None and len(data.credential_id) < 16:
            self._emit(
                "WAC-033",
                f"Attested credential ID is only {len(data.credential_id)} bytes",
                base + "/response/attestationObject/authData/credentialId",
                length=len(data.credential_id),
            )
        if (
            outer_id is not None
            and data.credential_id is not None
            and not hmac.compare_digest(outer_id, data.credential_id)
        ):
            self._emit(
                "WAC-044",
                "credential.rawId differs from the attested credential ID",
                base + "/rawId",
            )
        response_algorithm = response.get("publicKeyAlgorithm")
        if isinstance(response_algorithm, int) and response_algorithm != alg:
            self._emit(
                "WAC-035",
                f"response.publicKeyAlgorithm {response_algorithm} differs from COSE alg {alg}",
                base + "/response/publicKeyAlgorithm",
            )
        self.result.observations.update(
            {
                "credentialAlgorithm": alg,
                "credentialKeyType": kty,
                "credentialIdLength": len(data.credential_id or b""),
            }
        )

    def _audit_assertion_binding(
        self,
        credential: dict[str, Any],
        raw_id: bytes | None,
        options: dict[str, Any] | None,
        expected: dict[str, Any],
        base: str,
    ) -> None:
        if (
            options
            and isinstance(options.get("allowCredentials"), list)
            and options["allowCredentials"]
        ):
            allowed: list[bytes] = []
            for descriptor in options["allowCredentials"]:
                if isinstance(descriptor, dict):
                    try:
                        allowed.append(
                            b64url_decode(descriptor.get("id"), field="allowCredentials.id")
                        )
                    except DecodeError:
                        pass
            if raw_id is not None and not any(
                hmac.compare_digest(raw_id, item) for item in allowed
            ):
                self._emit(
                    "WAC-037", "Returned credential is outside allowCredentials", base + "/rawId"
                )
        body = credential.get("response", {})
        expected_handle = expected.get("userHandle")
        returned_handle = body.get("userHandle") if isinstance(body, dict) else None
        if expected_handle is not None:
            expected_raw = self._decode(
                expected_handle, "expected.userHandle", "/expected/userHandle"
            )
            returned_raw = self._decode(
                returned_handle, "response.userHandle", base + "/response/userHandle"
            )
            if (
                expected_raw is not None
                and returned_raw is not None
                and not hmac.compare_digest(expected_raw, returned_raw)
            ):
                self._emit(
                    "WAC-038",
                    "Returned user handle differs from expected account handle",
                    base + "/response/userHandle",
                )

    def _audit_client_extensions(
        self, credential: dict[str, Any], options: dict[str, Any] | None, base: str
    ) -> None:
        outputs = credential.get("clientExtensionResults", {})
        if not isinstance(outputs, dict):
            self._emit(
                "WAC-031",
                "clientExtensionResults must be an object",
                base + "/clientExtensionResults",
            )
            return
        requested = options.get("extensions", {}) if options else {}
        if not isinstance(requested, dict):
            requested = {}
        cred_props = outputs.get("credProps")
        if (
            self.policy.require_discoverable_credentials
            and isinstance(cred_props, dict)
            and cred_props.get("rk") is False
        ):
            self._emit(
                "WAC-024",
                "Credential Properties reports a non-discoverable credential",
                base + "/clientExtensionResults/credProps/rk",
            )
        for key in outputs:
            if key not in requested:
                self._emit(
                    "WAC-032",
                    f"Extension output {key!r} was not requested",
                    base + f"/clientExtensionResults/{key}",
                    extension=key,
                )
            if key not in KNOWN_EXTENSIONS:
                self._emit(
                    "WAC-040",
                    f"Unknown extension output {key!r}",
                    base + f"/clientExtensionResults/{key}",
                    extension=key,
                )

    def _origins(self, expected: dict[str, Any]) -> tuple[str, ...]:
        value = expected.get("origins")
        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            return tuple(value)
        single = expected.get("origin")
        if isinstance(single, str):
            return (single,)
        return self.policy.origins

    def _effective_rp_id(
        self, options: dict[str, Any] | None, expected: dict[str, Any]
    ) -> str | None:
        value = expected.get("rpId", self.policy.rp_id)
        if isinstance(value, str):
            return value
        if options:
            option_rp_id = options.get("rpId")
            if isinstance(option_rp_id, str):
                return option_rp_id
            rp = options.get("rp")
            if isinstance(rp, dict):
                nested_rp_id = rp.get("id")
                if isinstance(nested_rp_id, str):
                    return nested_rp_id
        origins = self._origins(expected)
        if len(origins) == 1:
            parsed = origin_host(origins[0])
            return parsed[1] if parsed else None
        return None


def audit_files(paths: list[Path], policy: Policy) -> AuditResult:
    from .artifacts import ArtifactError, load_json

    combined = AuditResult()
    expanded: list[Path] = []
    for path in paths:
        if path.is_dir():
            expanded.extend(sorted(item for item in path.rglob("*.json") if item.is_file()))
        else:
            expanded.append(path)
    if len(expanded) > 1_000:
        raise ArtifactError("artifact count exceeds the 1000-file limit")
    if not expanded:
        raise ArtifactError("no JSON artifacts found")
    for path in expanded:
        value = load_json(path)
        result = Auditor(policy).audit(value, str(path))
        combined.artifacts.extend(result.artifacts)
        combined.findings.extend(result.findings)
        if len(expanded) == 1:
            combined.observations.update(result.observations)
    return combined
