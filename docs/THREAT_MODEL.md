# Threat model

## Security objective

Help a relying-party operator identify captured WebAuthn data that would be
unsafe, inconsistent, privacy-invasive, or incompatible with declared policy
if accepted by a server.

## Untrusted inputs

All artifact bytes, JSON names and values, CBOR structures, credential responses,
browser-provided fields, filenames, and baseline contents are untrusted. The
parser applies file, decoded-value, CBOR depth, and CBOR item limits. Findings
summarize sensitive values instead of reproducing them.

## Trusted inputs

- The installed package and selected policy file.
- Explicit RP IDs and exact origin allowlists.
- Per-ceremony expected challenge, user handle, previous counter, and externally
  validated related-origin state.
- The environment that captured and transferred the artifact.

If an attacker can change expected values together with a response, correlation
checks cannot provide evidence of authenticity.

## In scope

- Replay and ceremony-type confusion.
- Origin, top-origin, RP-ID, credential, user, and algorithm binding.
- Authenticator flag invariants and policy requirements.
- Counter rollback evidence.
- Structural validation of attestation objects, authenticator data, COSE keys,
  credential descriptors, extensions, and serialized responses.
- Passkey discoverability and user-verification posture.
- Attestation and user-handle privacy signals.
- Deterministic, secret-minimized evidence for human review and CI.

## Out of scope in 0.1

- Verifying assertion or attestation signatures.
- Building and validating X.509 attestation trust paths.
- Querying or caching FIDO Metadata Service statements.
- Proving that a challenge was generated randomly, stored server-side, used once,
  or expired after the ceremony.
- Public Suffix List or related-origin network validation.
- Account recovery, session security, authorization, abuse prevention, browser
  compromise, malicious JavaScript, authenticator firmware, and endpoint security.
- Guaranteeing conformance, certification, regulatory compliance, or absence of
  vulnerabilities.

## Failure posture

Malformed evidence produces a finding or input error; it is never silently
treated as clean. Unsupported attestation semantics are observations, not trust
claims. Operational heuristics use low or informational severity unless they
violate an explicit profile or binding.
