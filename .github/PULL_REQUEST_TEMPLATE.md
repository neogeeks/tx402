<!--
Thanks for contributing to tx402! A few notes to make review fast:
- Keep changes focused; one concern per PR.
- The TypeScript and Python SDKs are kept at behavioural parity — a change to one usually
  needs the mirror in the other, and any change to observable behaviour needs a conformance
  fixture. See CONTRIBUTING.md.
-->

## Summary

<!-- What does this change and why? -->

## Related issue

<!-- e.g. Closes #123 -->

## Type of change

- [ ] Bug fix (no API change)
- [ ] New feature
- [ ] Breaking change (exported type removed, error code changed, default relaxed, or wire behaviour changed)
- [ ] Docs / internal only

## Checklist

- [ ] `pnpm check` passes locally (lint, typecheck, tests, conformance, size, docs) and the Python suite is green.
- [ ] If behaviour changed, I updated or added a conformance fixture in `core-spec/` and both SDKs pass it.
- [ ] If one SDK changed, the other is kept at parity (or the divergence is explained and justified).
- [ ] `CHANGELOG.md` is updated under `[Unreleased]` (breaking changes under a `### Breaking` heading).
- [ ] No private keys, tokens, signatures, or authorization payloads appear in code, tests, logs, or fixtures.
