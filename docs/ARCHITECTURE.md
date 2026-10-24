# Architecture

The project is intentionally a bounded batch analyzer rather than a WebAuthn
server or network scanner.

```text
JSON files/directories
        │
        ▼
 bounded loader ──► artifact classifier ──► strict base64url/JSON/CBOR decoders
                                             │
                                             ▼
 trusted policy ───────────────────────► normalized ceremony model
                                             │
                                             ▼
                                      independent rule checks
                                             │
                           ┌─────────────────┼─────────────────┐
                           ▼                 ▼                 ▼
                         text              JSON             SARIF
```

## Modules

- `artifacts.py` loads and classifies JSON, parses attestation objects and the
  authenticator-data byte layout, and derives RP-ID bindings.
- `codec.py` performs bounded base64url and client-data decoding.
- `cbor.py` is a deliberately small, defensive decoder for the CBOR subset
  needed by WebAuthn. It rejects indefinite-length items, duplicate map keys,
  excessive depth, excessive items, trailing bytes, and non-finite floats.
- `audit.py` correlates options, signed client data, authenticator evidence,
  stored expectations, and policy. Checks do not mutate artifacts.
- `catalog.py` is the canonical rule metadata and normative-reference registry.
- `reporting.py` emits deterministic, secret-minimized text, JSON, and SARIF.
- `config.py` maps explicit TOML policy onto immutable typed settings.

## Design invariants

1. Default execution performs no network access.
2. Malformed evidence never becomes a clean result.
3. Reports do not reproduce credential material.
4. Binding comparisons use decoded bytes and constant-time comparison where
   the values are security-sensitive.
5. Every finding has a stable ID, severity, remediation, location, and primary
   specification reference.
6. Limits are enforced before or during recursive decoding.
7. Unsupported cryptographic trust decisions are named as limitations rather
   than approximated.
