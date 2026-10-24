# webauthn-audit

`webauthn-audit` is an offline-first security auditor for WebAuthn and passkey
options, credential responses, and complete ceremonies. It correlates what a
relying party issued with what the browser and authenticator returned, parses
the signed binary evidence, and produces deterministic text, JSON, or SARIF.

It never contacts an origin, metadata service, or authenticator. Reports contain
lengths, flags, algorithm identifiers, and hashes where useful—not raw challenges,
credential IDs, signatures, user handles, public keys, or certificates.

> WebAuthn responses are untrusted input. This tool is an auditor, not a replacement
> for a conforming server-side WebAuthn verification library.

## What it audits

- creation and request options, including challenge entropy, RP IDs, origins,
  user handles, algorithms, timeouts, credential descriptors, authenticator
  selection, discoverability, user verification, hints, extensions, and attestation;
- registration and authentication responses serialized with
  `PublicKeyCredential.toJSON()` or the equivalent base64url representation;
- `clientDataJSON` type, challenge, origin, `crossOrigin`, `topOrigin`, and legacy fields;
- CBOR attestation objects and attestation format policy;
- authenticator data: RP-ID hash, UP/UV/BE/BS/AT/ED and reserved flags,
  signature counters, AAGUID, credential ID, COSE public key, and extension output;
- cross-artifact bindings: issued/returned challenge, offered/returned algorithm,
  `allowCredentials`, user handle, RP ID, origin, and previous signature counter;
- baseline suppression for gradual adoption and SARIF 2.1.0 for GitHub code scanning.

The initial catalog contains 45 stable rule IDs. Run `webauthn-audit rules` to
list every rule and its normative WebAuthn reference.

## Install

Requires Python 3.10 or newer and has no runtime dependency on Python 3.11+.

```bash
python -m pip install -e .
webauthn-audit --version
```

## Quick start

Audit one or more standalone option/response objects:

```bash
webauthn-audit lint registration-options.json authentication-response.json
```

Audit a paired passkey ceremony and fail CI on medium or higher findings:

```bash
webauthn-audit lint ceremony.json \
  --profile passkey \
  --fail-on medium
```

Create SARIF:

```bash
webauthn-audit lint ceremony.json \
  --config webauthn-audit.toml \
  --format sarif \
  --output webauthn-audit.sarif
```

Exit codes are `0` for clean/below threshold, `2` when findings meet the failure
threshold, and `3` for invalid input, configuration, or output errors.

## Paired ceremony format

Correlation checks require the issued options and returned credential together:

```json
{
  "creationOptions": {
    "publicKey": {
      "challenge": "base64url...",
      "rp": {"id": "login.example.com", "name": "Example"},
      "user": {"id": "opaque-base64url...", "name": "account", "displayName": "Account"},
      "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
      "authenticatorSelection": {
        "residentKey": "required",
        "userVerification": "required"
      },
      "attestation": "none"
    }
  },
  "credential": {
    "id": "base64url...",
    "rawId": "base64url...",
    "type": "public-key",
    "response": {
      "clientDataJSON": "base64url...",
      "attestationObject": "base64url..."
    },
    "clientExtensionResults": {}
  },
  "expected": {
    "rpId": "login.example.com",
    "origins": ["https://login.example.com"],
    "requireUserVerification": true
  }
}
```

For authentication use `requestOptions`, and optionally put `previousSignCount`
and the expected base64url `userHandle` under `expected`.

Inputs should come from test systems or deliberately sanitized captures. Never
commit production ceremonies: public keys, credential IDs and attestation
certificates are not passwords, but they can still be identifying or operationally sensitive.

## Profiles

| Profile | Intended use | Defaults |
|---|---|---|
| `baseline` | General WebAuthn deployments | Standards violations and unsafe structures |
| `passkey` | Passwordless consumer sign-in | Requires UV and discoverable credentials |
| `high-assurance` | Enterprise or sensitive systems | Requires UV; fails CI from low severity |

Profiles are starting points, not claims of regulatory compliance. In particular,
attestation trust, account recovery, credential lifecycle, rate limiting, session
management, and risk response remain relying-party responsibilities.

## Configuration

```toml
[policy]
profile = "passkey"
rp_id = "login.example.com"
origins = ["https://login.example.com"]
require_user_verification = true
require_discoverable_credentials = true
allow_cross_origin = false
allow_related_origins = false
allowed_algorithms = [-7, -8, -257]
allowed_attestation_formats = ["none", "packed", "apple"]
previous_sign_count = 41
fail_on = "medium"
suppress = []
```

Envelope `expected` values describe a particular ceremony and take precedence
over reusable policy values where appropriate.

Set `allow_related_origins=true` only after separately validating the RP's
`/.well-known/webauthn` response. A single envelope may instead set
`expected.relatedOriginsValidated=true` to record that external validation.

## Baselines

Save a JSON report, then report only new fingerprints:

```bash
webauthn-audit lint captures/ --format json --output baseline.json
webauthn-audit lint captures/ --baseline baseline.json
```

Fingerprints include the rule, artifact, JSON pointer, and normalized message.
Moving an artifact intentionally creates a new review item.

## CI

```yaml
permissions:
  contents: read
  security-events: write

- uses: actions/checkout@v4
- uses: Liam-G/webauthn-audit@v1
  with:
    artifacts: "tests/webauthn"
    profile: passkey
    fail-on: medium
```

The bundled action installs the checked-out project, writes SARIF, and uploads it
when GitHub code scanning is available. For forks or restricted repositories,
run the CLI directly and upload the artifact according to local policy.

## Security boundaries and intentional limitations

`webauthn-audit` validates captured structure and consistency. Version 0.1 does
not perform attestation certificate-chain validation, FIDO Metadata Service
lookups, assertion signature verification, Public Suffix List resolution, or
browser automation. Those operations require additional trusted inputs or
network/state boundaries and must not be silently approximated.

The RP-ID suffix check is deliberately conservative but cannot prove that a
suffix is registrable without a Public Suffix List. Browsers remain the final
authority during option processing; servers must still validate exact configured
RP IDs and origins.

## References

- [Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)
- [FIDO Alliance passkey deployment guidance](https://fidoalliance.org/passkeys/)
- [IANA COSE registry](https://www.iana.org/assignments/cose/cose.xhtml)
- [RFC 8949: CBOR](https://www.rfc-editor.org/rfc/rfc8949)
- [RFC 9052 and RFC 9053: COSE](https://www.rfc-editor.org/rfc/rfc9052)

See [the complete rule catalog](docs/RULES.md) and
[threat model](docs/THREAT_MODEL.md) for review boundaries and severity rationale.
Machine consumers can use the checked-in
[ceremony-envelope](schemas/ceremony-envelope.schema.json) and
[report](schemas/report.schema.json) JSON Schemas.

## Development

```bash
python -m pip install -e '.[dev]'
pytest
ruff check .
mypy src
```

Security-sensitive changes should include a positive fixture, a negative fixture,
and the exact normative reference that justifies the behavior.

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and the
[Code of Conduct](CODE_OF_CONDUCT.md) before opening a contribution.

## License

MIT
