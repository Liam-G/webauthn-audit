from __future__ import annotations

import hashlib
import json

from webauthn_audit.artifacts import parse_authenticator_data, rp_id_matches_origin
from webauthn_audit.audit import Auditor
from webauthn_audit.models import Policy

from .helpers import CHALLENGE, ORIGIN, RP_ID, authentication_envelope, b64, registration_envelope


def ids(value: dict, profile: str = "passkey") -> set[str]:
    return {
        finding.rule.id for finding in Auditor(Policy.for_profile(profile)).audit(value).findings
    }


def test_good_registration_and_authentication_are_clean() -> None:
    assert ids(registration_envelope()) == set()
    assert ids(authentication_envelope()) == set()


def test_registration_detects_policy_and_binding_failures() -> None:
    value = registration_envelope()
    options = value["creationOptions"]["publicKey"]
    options["challenge"] = b64(b"short")
    options["user"]["id"] = b64(b"person@example.com")
    options["pubKeyCredParams"] = [{"type": "public-key", "alg": -65535}]
    options["authenticatorSelection"] = {
        "residentKey": "discouraged",
        "requireResidentKey": True,
        "userVerification": "discouraged",
    }
    options["attestation"] = "direct"
    found = ids(value)
    assert {
        "WAC-002",
        "WAC-003",
        "WAC-012",
        "WAC-020",
        "WAC-021",
        "WAC-023",
        "WAC-024",
        "WAC-025",
        "WAC-026",
    } <= found


def test_client_data_origin_type_and_cross_origin() -> None:
    value = registration_envelope()
    client = {
        "type": "webauthn.get",
        "challenge": b64(CHALLENGE),
        "origin": "https://evil.example",
        "crossOrigin": True,
        "topOrigin": "https://evil.example",
        "tokenBinding": {"status": "supported"},
    }
    value["credential"]["response"]["clientDataJSON"] = b64(json.dumps(client).encode())
    found = ids(value)
    assert {"WAC-004", "WAC-005", "WAC-006", "WAC-007", "WAC-041"} <= found


def test_authentication_detects_counter_rp_flags_allowlist_and_handle() -> None:
    value = authentication_envelope()
    value["requestOptions"]["publicKey"]["allowCredentials"][0]["id"] = b64(b"z" * 32)
    value["expected"]["userHandle"] = b64(b"different-handle")
    auth = b"\x00" * 32 + bytes([0x32]) + (7).to_bytes(4, "big")
    value["credential"]["response"]["authenticatorData"] = b64(auth)
    found = ids(value)
    assert {
        "WAC-010",
        "WAC-011",
        "WAC-013",
        "WAC-014",
        "WAC-015",
        "WAC-018",
        "WAC-037",
        "WAC-038",
    } <= found


def test_malformed_values_are_findings_not_crashes() -> None:
    value = registration_envelope()
    value["credential"]["rawId"] = "***"
    value["credential"]["response"]["attestationObject"] = b64(b"not-cbor")
    found = ids(value)
    assert "WAC-001" in found


def test_authenticator_parser_and_origin_matching() -> None:
    raw = hashlib.sha256(RP_ID.encode()).digest() + b"\x01" + b"\x00\x00\x00\x02"
    parsed = parse_authenticator_data(raw)
    assert parsed.up and parsed.sign_count == 2 and not parsed.at
    assert rp_id_matches_origin(RP_ID, ORIGIN)
    assert rp_id_matches_origin("example.test", ORIGIN)
    assert not rp_id_matches_origin("ample.test", ORIGIN)
    assert rp_id_matches_origin("example.test", "http://login.example.test")
    assert not rp_id_matches_origin("127.0.0.1", "https://127.0.0.1")


def test_unrequested_extension_and_mismatched_ids() -> None:
    value = authentication_envelope()
    value["credential"]["id"] = b64(b"q" * 32)
    value["credential"]["clientExtensionResults"] = {"unknownThing": True}
    assert {"WAC-029", "WAC-032", "WAC-040"} <= ids(value)


def test_attested_credential_and_backup_eligibility_bindings() -> None:
    registration = registration_envelope()
    registration["credential"]["rawId"] = b64(b"q" * 32)
    registration["credential"]["id"] = b64(b"q" * 32)
    assert "WAC-044" in ids(registration)

    authentication = authentication_envelope()
    authentication["expected"]["backupEligible"] = False
    assert "WAC-043" in ids(authentication)
