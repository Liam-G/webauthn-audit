from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from webauthn_audit.artifacts import ArtifactError, load_json, origin_host, unwrap_options
from webauthn_audit.audit import Auditor
from webauthn_audit.cbor import CBORError, Decoder, decode_one
from webauthn_audit.cli import main
from webauthn_audit.config import ConfigError, load_policy
from webauthn_audit.models import AuditResult, Policy, Severity
from webauthn_audit.reporting import baseline_fingerprints, render_json, render_sarif, render_text

from .helpers import authentication_envelope, b64, cbor, registration_envelope


def test_standalone_bad_options_cover_validation_paths() -> None:
    value = {
        "publicKey": {
            "challenge": b64(b"x" * 32),
            "rp": {"id": "evil.test"},
            "user": {"id": b64(b""), "name": "x", "displayName": "x"},
            "pubKeyCredParams": [
                {"type": "wrong", "alg": "-7"},
                {"type": "public-key", "alg": -7},
                {"type": "public-key", "alg": -7},
            ],
            "timeout": "forever",
            "excludeCredentials": "bad",
            "hints": ["unknown"],
            "extensions": [],
        }
    }
    policy = Policy(
        profile="baseline", rp_id="evil.test", origins=("http://remote.test", "not an origin")
    )
    found = {f.rule.id for f in Auditor(policy).audit(value).findings}
    assert {
        "WAC-001",
        "WAC-005",
        "WAC-008",
        "WAC-009",
        "WAC-022",
        "WAC-028",
        "WAC-031",
        "WAC-039",
        "WAC-040",
    } <= found


def test_credential_schema_and_extension_errors() -> None:
    value = authentication_envelope()
    value["credential"]["type"] = "password"
    value["credential"]["response"]["signature"] = b64(b"x")
    value["credential"]["clientExtensionResults"] = []
    found = {f.rule.id for f in Auditor(Policy.for_profile("passkey")).audit(value).findings}
    assert {"WAC-030", "WAC-031", "WAC-036"} <= found


def test_registration_attestation_policy_and_bad_cose_key() -> None:
    value = registration_envelope()
    policy = Policy(profile="baseline", allowed_attestation_formats=("packed",))
    found = {f.rule.id for f in Auditor(policy).audit(value).findings}
    assert "WAC-027" in found


def test_policy_and_severity_errors() -> None:
    with pytest.raises(ValueError):
        Policy.for_profile("unknown")
    with pytest.raises(ValueError):
        Severity.parse("urgent")


@pytest.mark.parametrize(
    "body",
    [
        "[policy]\nprofile=4\n",
        '[policy]\norigins="x"\n',
        "[policy]\nrp_id=3\n",
        "[policy]\nfail_on=3\n",
        "[policy]\nprevious_sign_count=-1\n",
        '[policy]\nallow_cross_origin="yes"\n',
    ],
)
def test_more_invalid_configs(tmp_path, body: str) -> None:
    path = tmp_path / "bad.toml"
    path.write_text(body)
    with pytest.raises(ConfigError):
        load_policy(path)


def test_artifact_loading_failures(tmp_path) -> None:
    missing = tmp_path / "missing.json"
    with pytest.raises(ArtifactError):
        load_json(missing)
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{")
    with pytest.raises(ArtifactError):
        load_json(invalid)
    large = tmp_path / "large.json"
    large.write_text("[]")
    with pytest.raises(ArtifactError):
        load_json(large, max_bytes=1)


def test_reporting_all_formats_and_bad_baseline(tmp_path) -> None:
    policy = Policy.for_profile("passkey")
    result = Auditor(policy).audit({"no": "artifact"}, "bad.json")
    assert "WAC-030" in render_text(result, policy)
    assert "No findings" in render_text(AuditResult(), policy)
    assert json.loads(render_json(result, policy))["summary"]["total"] == 1
    sarif = json.loads(render_sarif(result, policy))
    assert sarif["runs"][0]["results"][0]["level"] == "error"
    bad = tmp_path / "baseline.json"
    bad.write_text("{}")
    with pytest.raises(ValueError):
        baseline_fingerprints(bad)


def test_cli_error_and_text_output(tmp_path, capsys) -> None:
    missing = tmp_path / "missing.json"
    assert main(["lint", str(missing)]) == 3
    assert "error" in capsys.readouterr().err
    artifact = tmp_path / "bad.json"
    artifact.write_text(json.dumps({"no": "artifact"}))
    assert main(["lint", str(artifact), "--no-color"]) == 2
    assert "WAC-030" in capsys.readouterr().out


def test_cbor_additional_types_and_limits() -> None:
    assert decode_one(b"\xc1\x01")[0] == {"__cbor_tag__": 1, "value": 1}
    assert decode_one(b"\xf8\x18")[0] == {"__cbor_simple__": 24}
    assert decode_one(b"\xfa" + struct.pack(">f", 1.5))[0] == 1.5
    with pytest.raises(CBORError):
        decode_one(b"\xff")
    with pytest.raises(CBORError):
        Decoder(cbor([[[1]]]), max_depth=1).decode()
    with pytest.raises(CBORError):
        Decoder(cbor([1, 2]), max_items=1).decode()


def test_option_unwrap_and_origin_edge_cases() -> None:
    assert unwrap_options([]) is None
    assert unwrap_options({"publicKey": []}) is None
    assert origin_host("https://user@example.test") is None
    assert origin_host("https://example.test/path") is None
    assert origin_host("https://example.test") == ("https", "example.test")


def test_minimal_request_options_and_directory_scan(tmp_path, capsys) -> None:
    minimal = {"publicKey": {"challenge": b64(b"c" * 32)}}
    assert Auditor(Policy.for_profile("baseline")).audit(minimal).findings == []
    folder = tmp_path / "captures"
    folder.mkdir()
    (folder / "one.json").write_text(json.dumps(minimal))
    (folder / "two.json").write_text(json.dumps(minimal))
    assert main(["lint", str(folder), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["artifacts"] == [
        str(folder / "one.json"),
        str(folder / "two.json"),
    ]


def test_standalone_response_reports_missing_trusted_context() -> None:
    credential = authentication_envelope()["credential"]
    found = {
        finding.rule.id
        for finding in Auditor(Policy.for_profile("baseline")).audit(credential).findings
    }
    assert "WAC-045" in found


def test_checked_in_json_schemas_parse() -> None:
    root = Path(__file__).parents[1]
    envelope = json.loads((root / "schemas/ceremony-envelope.schema.json").read_text())
    report = json.loads((root / "schemas/report.schema.json").read_text())
    assert envelope["$schema"].endswith("2020-12/schema")
    assert report["properties"]["schemaVersion"]["const"] == "1.0"
