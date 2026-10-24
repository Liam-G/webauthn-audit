## Summary

Describe the behavior, threat model, and normative source.

## Security checklist

- [ ] No raw challenge, credential ID, user handle, signature, public key, or certificate is reported.
- [ ] Parser changes retain explicit size, depth, and item bounds.
- [ ] New or changed findings cite a primary specification.
- [ ] Positive, negative, and malformed-input tests are included.
- [ ] `pytest`, `ruff check .`, and `mypy src` pass.
- [ ] User-facing and machine-readable output changes are documented.
