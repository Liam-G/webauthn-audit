# Security policy

Please report vulnerabilities privately through GitHub Security Advisories for
`Liam-G/webauthn-audit`. Do not include production credential captures, user
handles, signatures, certificates, or private deployment configuration in a report.

Supported releases are the latest tagged release and the current `main` branch.

`webauthn-audit` parses attacker-controlled JSON, base64url, CBOR, and
authenticator data. Its decoders enforce input-size, nesting, and item-count
limits. A crash, unbounded resource use, secret disclosure, misleading clean
result, or bypass of a high/critical rule is considered security-relevant.
