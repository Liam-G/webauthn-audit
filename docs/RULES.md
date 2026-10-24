# Rule catalog

Rule IDs and meanings are stable within a major release. Severity expresses the
default risk of accepting an artifact as-is; deployments may raise thresholds
or suppress contextual findings in configuration.

| ID | Severity | Check |
|---|---|---|
| WAC-001 | high | Malformed security-relevant base64url, JSON, CBOR, or authenticator data |
| WAC-002 | high | Challenge shorter than the WebAuthn 16-byte recommendation |
| WAC-003 | critical | Returned challenge differs from issued challenge |
| WAC-004 | critical | `clientDataJSON.type` differs from the expected ceremony |
| WAC-005 | critical | Signed origin is outside the exact allowlist |
| WAC-006 | high | Cross-origin ceremony is not allowed by policy |
| WAC-007 | critical | Signed `topOrigin` is outside the allowlist |
| WAC-008 | critical | RP ID is incompatible with the origin |
| WAC-009 | high | Non-HTTPS origin other than HTTP localhost |
| WAC-010 | critical | Authenticator RP-ID hash mismatch |
| WAC-011 | high | User-presence flag absent |
| WAC-012 | medium | User verification not required under the selected profile |
| WAC-013 | high | Required user-verification flag absent |
| WAC-014 | medium | Reserved authenticator flag set |
| WAC-015 | high | Backup-state flag set without backup eligibility |
| WAC-016 | high | Assertion contains attested credential data |
| WAC-017 | high | Registration lacks attested credential data |
| WAC-018 | medium | Non-zero signature counter failed to increase |
| WAC-019 | high | User handle outside the 1–64-byte range |
| WAC-020 | medium | User handle resembles email or telephone PII |
| WAC-021 | high | No policy-allowed credential algorithm |
| WAC-022 | medium | Duplicate or malformed algorithm entry |
| WAC-023 | high | Legacy RS1/SHA-1 algorithm offered |
| WAC-024 | medium | Passkey profile does not require discoverability |
| WAC-025 | high | Contradictory resident-key options |
| WAC-026 | medium | Privacy-sensitive attestation requested |
| WAC-027 | high | Returned attestation format violates policy |
| WAC-028 | high | Malformed or duplicate credential descriptor |
| WAC-029 | high | Credential `id` and `rawId` disagree |
| WAC-030 | critical | Required response field missing |
| WAC-031 | medium | Extension structure or ED flag inconsistent |
| WAC-032 | low | Client returned an unrequested extension output |
| WAC-033 | medium | Credential ID unusually short |
| WAC-034 | critical | Attested COSE public key malformed |
| WAC-035 | critical | Returned credential algorithm was not offered |
| WAC-036 | high | Response is not a public-key credential |
| WAC-037 | critical | Assertion credential absent from `allowCredentials` |
| WAC-038 | critical | Assertion user handle differs from expected account |
| WAC-039 | low | Timeout outside the recommended 300–600-second range |
| WAC-040 | low | Unknown authenticator hint, transport, or extension |
| WAC-041 | info | Obsolete Token Binding field present |
| WAC-042 | info | Capture contains sensitive attestation evidence |
| WAC-043 | critical | Immutable backup-eligibility state changed |
| WAC-044 | critical | Outer and attested credential IDs differ |
| WAC-045 | medium | Trusted verification context is incomplete |

Run `webauthn-audit rules` for normative links. The CLI is the canonical,
version-specific rule inventory.
