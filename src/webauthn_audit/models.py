from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            allowed = ", ".join(item.name.lower() for item in cls)
            raise ValueError(f"unknown severity {value!r}; expected one of: {allowed}") from exc


@dataclass(frozen=True)
class Reference:
    title: str
    url: str


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    references: tuple[Reference, ...]
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class Location:
    artifact: str
    pointer: str = ""


@dataclass(frozen=True)
class Finding:
    rule: Rule
    message: str
    location: Location
    evidence: dict[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        import hashlib

        material = (
            f"{self.rule.id}\0{self.location.artifact}\0{self.location.pointer}\0{self.message}"
        )
        return hashlib.sha256(material.encode()).hexdigest()


@dataclass(frozen=True)
class Policy:
    profile: str = "baseline"
    rp_id: str | None = None
    origins: tuple[str, ...] = ()
    require_user_verification: bool = False
    require_discoverable_credentials: bool = False
    allow_cross_origin: bool = False
    allow_related_origins: bool = False
    allowed_algorithms: tuple[int, ...] = (-7, -8, -257)
    allowed_attestation_formats: tuple[str, ...] = ()
    previous_sign_count: int | None = None
    fail_on: Severity = Severity.MEDIUM
    suppress: frozenset[str] = frozenset()

    @classmethod
    def for_profile(cls, name: str) -> Policy:
        if name == "baseline":
            return cls(profile=name)
        if name == "passkey":
            return cls(
                profile=name,
                require_user_verification=True,
                require_discoverable_credentials=True,
            )
        if name == "high-assurance":
            return cls(
                profile=name,
                require_user_verification=True,
                require_discoverable_credentials=False,
                allowed_algorithms=(-7, -8, -257),
                fail_on=Severity.LOW,
            )
        raise ValueError("profile must be baseline, passkey, or high-assurance")


@dataclass
class AuditResult:
    artifacts: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    observations: dict[str, Any] = field(default_factory=dict)

    def active(self, policy: Policy) -> list[Finding]:
        return sorted(
            (f for f in self.findings if f.rule.id not in policy.suppress),
            key=lambda f: (-int(f.rule.severity), f.rule.id, f.location.pointer),
        )
