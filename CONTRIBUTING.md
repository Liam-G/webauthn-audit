# Contributing

1. Open an issue describing the behavior and its normative source.
2. Add paired vulnerable and acceptable test cases.
3. Keep rule IDs stable; add new IDs instead of changing established meaning.
4. Never add network access to the default audit path.
5. Never render raw challenges, credential IDs, user handles, signatures,
   public keys, or certificates in findings.
6. Run `pytest`, `ruff check .`, and `mypy src` before submitting a change.

False positives and false negatives are bugs. Rule changes should explain the
deployment assumptions that separate a standards violation, security weakness,
privacy concern, interoperability issue, and informational observation.
