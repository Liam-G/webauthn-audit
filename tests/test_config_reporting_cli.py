from __future__ import annotations

import json

import pytest

from webauthn_audit.cli import main
from webauthn_audit.config import ConfigError, load_policy
from webauthn_audit.models import Severity

from .helpers import authentication_envelope, registration_envelope


def test_config_overrides_profile(tmp_path) -> None:
    path = tmp_path / "audit.toml"
    path.write_text(
        '[policy]\nprofile="passkey"\nrp_id="example.test"\norigins=["https://example.test"]\nfail_on="high"\nsuppress=["WAC-039"]\n'
    )
    policy = load_policy(path)
    assert policy.profile == "passkey"
    assert policy.require_user_verification
    assert policy.fail_on == Severity.HIGH
    assert "WAC-039" in policy.suppress


def test_invalid_config(tmp_path) -> None:
    path = tmp_path / "bad.toml"
    path.write_text('[policy]\nallowed_algorithms=["ES256"]\n')
    with pytest.raises(ConfigError):
        load_policy(path)


@pytest.mark.parametrize(
    "body",
    [
        '[policy]\nprofilo="passkey"\n',
        '[policy]\nsuppress=["WAC-999"]\n',
    ],
)
def test_config_rejects_unknown_keys_and_rule_ids(tmp_path, body: str) -> None:
    path = tmp_path / "unknown.toml"
    path.write_text(body)
    with pytest.raises(ConfigError):
        load_policy(path)


def test_cli_clean_json_and_sarif(tmp_path, capsys) -> None:
    artifact = tmp_path / "good.json"
    artifact.write_text(json.dumps(registration_envelope()))
    assert main(["lint", str(artifact), "--profile", "passkey", "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["total"] == 0
    output = tmp_path / "result.sarif"
    assert (
        main(
            [
                "lint",
                str(artifact),
                "--profile",
                "passkey",
                "--format",
                "sarif",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert json.loads(output.read_text())["version"] == "2.1.0"


def test_cli_findings_and_baseline(tmp_path, capsys) -> None:
    value = authentication_envelope()
    value["credential"]["response"]["authenticatorData"] = "bad***"
    artifact = tmp_path / "bad.json"
    artifact.write_text(json.dumps(value))
    assert main(["lint", str(artifact), "--profile", "passkey", "--format", "json"]) == 2
    report_text = capsys.readouterr().out
    report = json.loads(report_text)
    assert report["summary"]["total"] >= 1
    baseline = tmp_path / "baseline.json"
    baseline.write_text(report_text)
    assert main(["lint", str(artifact), "--profile", "passkey", "--baseline", str(baseline)]) == 0


def test_rules_command(capsys) -> None:
    assert main(["rules"]) == 0
    output = capsys.readouterr().out
    assert "WAC-001" in output and "WAC-045" in output
