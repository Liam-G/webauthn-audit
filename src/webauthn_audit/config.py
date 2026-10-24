from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from .models import Policy, Severity

POLICY_KEYS = {
    "profile",
    "rp_id",
    "origins",
    "require_user_verification",
    "require_discoverable_credentials",
    "allow_cross_origin",
    "allow_related_origins",
    "allowed_algorithms",
    "allowed_attestation_formats",
    "previous_sign_count",
    "fail_on",
    "suppress",
}


class ConfigError(ValueError):
    pass


def load_policy(path: Path | None, *, profile: str | None = None) -> Policy:
    data: dict[str, Any] = {}
    if path is not None:
        try:
            with path.open("rb") as handle:
                loaded = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(f"cannot load {path}: {exc}") from exc
        if not isinstance(loaded, dict) or not isinstance(loaded.get("policy", {}), dict):
            raise ConfigError("configuration must contain a [policy] table")
        data = loaded.get("policy", {})
        unknown = sorted(set(data).difference(POLICY_KEYS))
        if unknown:
            raise ConfigError(f"unknown policy key(s): {', '.join(unknown)}")
    selected = profile or data.get("profile", "baseline")
    if not isinstance(selected, str):
        raise ConfigError("policy.profile must be a string")
    try:
        policy = Policy.for_profile(selected)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc

    def strings(key: str, default: tuple[str, ...]) -> tuple[str, ...]:
        value = data.get(key, list(default))
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ConfigError(f"policy.{key} must be an array of strings")
        return tuple(value)

    def integers(key: str, default: tuple[int, ...]) -> tuple[int, ...]:
        value = data.get(key, list(default))
        if not isinstance(value, list) or not all(
            isinstance(item, int) and not isinstance(item, bool) for item in value
        ):
            raise ConfigError(f"policy.{key} must be an array of integers")
        return tuple(value)

    rp_id = data.get("rp_id", policy.rp_id)
    if rp_id is not None and not isinstance(rp_id, str):
        raise ConfigError("policy.rp_id must be a string")
    fail_on = data.get("fail_on", policy.fail_on.name.lower())
    if not isinstance(fail_on, str):
        raise ConfigError("policy.fail_on must be a severity string")
    try:
        threshold = Severity.parse(fail_on)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
    previous = data.get("previous_sign_count", policy.previous_sign_count)
    if previous is not None and (
        not isinstance(previous, int) or isinstance(previous, bool) or previous < 0
    ):
        raise ConfigError("policy.previous_sign_count must be a non-negative integer")
    for key in (
        "require_user_verification",
        "require_discoverable_credentials",
        "allow_cross_origin",
        "allow_related_origins",
    ):
        if key in data and not isinstance(data[key], bool):
            raise ConfigError(f"policy.{key} must be a boolean")
    suppressed = frozenset(strings("suppress", tuple(policy.suppress)))
    from .catalog import RULES

    unknown_rules = sorted(suppressed.difference(RULES))
    if unknown_rules:
        raise ConfigError(f"unknown suppressed rule(s): {', '.join(unknown_rules)}")
    return replace(
        policy,
        rp_id=rp_id,
        origins=strings("origins", policy.origins),
        require_user_verification=data.get(
            "require_user_verification", policy.require_user_verification
        ),
        require_discoverable_credentials=data.get(
            "require_discoverable_credentials", policy.require_discoverable_credentials
        ),
        allow_cross_origin=data.get("allow_cross_origin", policy.allow_cross_origin),
        allow_related_origins=data.get("allow_related_origins", policy.allow_related_origins),
        allowed_algorithms=integers("allowed_algorithms", policy.allowed_algorithms),
        allowed_attestation_formats=strings(
            "allowed_attestation_formats", policy.allowed_attestation_formats
        ),
        previous_sign_count=previous,
        fail_on=threshold,
        suppress=suppressed,
    )
