# Conformance fixtures and runner contract

ADR-005 makes TypeScript the reference implementation and requires Python to pass the same
language-neutral vectors. This directory is those vectors, plus the rules a runner must
follow. Neither SDK may keep a private fixture: if a behavior is worth testing twice, it is
worth testing from one file.

```
index.json          the fixture index — ids, kinds, milestones, and content hashes
vectors/            the fixtures themselves, grouped by area
```

## The fixture format

Every vector is a self-contained JSON document validated against
[`../schemas/conformance-vector.schema.json`](../schemas/conformance-vector.schema.json).

```jsonc
{
  "id": "manifest.verify.expired", // globally unique, stable, never reused
  "kind": "manifest.verify", // selects the handler
  "milestone": "M0", // when an implementation must execute it
  "title": "…", // one line, shown in test output
  "description": "…", // optional; why this case matters
  "spec": ["SPEC §5.4"], // the clauses it pins — never empty
  "input": {}, // kind-specific
  "expected": {}, // kind-specific
}
```

`spec` is required and non-empty on purpose. A vector that cannot cite a requirement is
testing an implementation detail rather than a contract, and implementation details are
free to differ between the two languages.

## The index

`index.json` records every vector's `id`, `kind`, `milestone`, path, and the SHA-256 of its
exact file bytes.

Runners load the index rather than globbing the directory, and they verify each hash before
executing. Globbing would silently pass when a vector was deleted and silently execute one
that had been edited — neither is acceptable for artifacts SEC-007 requires to be integrity
checked before release.

Regenerate the index after any fixture change:

```bash
node tools/conformance/index.js build   # rewrite index.json
node tools/conformance/index.js check   # CI: fail if the index and the vectors disagree
```

`build` also validates every vector against the schema, so a malformed fixture fails once,
here, instead of twice in two different language runners.

## Two-stage execution

A vector is written when the _contract_ is frozen, which is generally earlier than when the
implementation lands. Rather than leave those vectors dormant, runners execute them in two
stages.

**Stage A — validate the vector.** Runs for _every_ vector, in both languages, from M0
onward, regardless of milestone:

- the file's SHA-256 matches `index.json`
- the document validates against `conformance-vector.schema.json`
- every `errorCode` it names exists in the frozen taxonomy
- every expected normalized output validates against its schema in `../schemas/`

Stage A is not a placeholder. It is what keeps the fixtures honest against the frozen names:
a vector expecting an error code that no longer exists, or a normalized shape that no longer
validates, fails immediately — long before the code that would produce it is written.

**Stage B — run the implementation.** Runs only where the language has registered a handler
for the vector's `kind`. The handler receives `input` and must produce `expected`.

**The rule that stops silent gaps:** each runner declares the milestone it implements
through. A vector at or below that milestone **must** have a Stage B handler; if it does
not, the runner fails. Vectors above it are reported as pending, with a count, so that an
unimplemented milestone is visible in test output rather than invisible.

```
IMPLEMENTED_THROUGH = "M0"    ->  M0 vectors must execute; M1+ are Stage A only
```

Raising that constant is how a milestone is claimed, and it cannot be raised without
registering the handlers, because the runner checks.

## Vector kinds

| Kind                               | Milestone | Executes                                                     |
| :--------------------------------- | :-------- | :----------------------------------------------------------- |
| `errors.taxonomy`                  | M0        | The SDK's error table against the frozen SPEC §8 rows        |
| `canonical-json`                   | M0        | `canonicalizeJson` / `canonicalize_json`                     |
| `manifest.verify`                  | M0        | Offline manifest verification, including the failure reason  |
| `manifest.network-resolution`      | M0        | CAIP-2 alias resolution (ADR-010 decision 4)                 |
| `protocol.decode-payment-required` | M1        | Strict v2 decode and normalization                           |
| `request.fingerprint`              | M2        | SEC-009 URL normalization, body digest, and fingerprint      |
| `spend-ledger.behavior`            | M2        | Reserve/commit/release transitions and the rolling-hour cap  |
| `evm.authorization-plan`           | M3        | EIP-3009 plan derivation and the lifetime clamp (SPEC §7.1)  |
| `svm.authorization-plan`           | M4        | ATA derivation, fee payer, Token-2022 exclusion (SPEC §7.2)  |
| `routing.candidate-order`          | M5        | The SPEC §6.4 step 18 ordering cascade                       |
| `health.circuit`                   | M5        | The SPEC §6.5 EWMA, thresholds, and open/half-open lifecycle |
| `completion.paid-attempt`          | M6        | The SPEC §6.7 disposition table for one signed attempt       |

Adding a kind means adding it to the schema enum, registering a handler in both languages,
and writing at least one valid and one invalid vector.

## Determinism

Nothing in a vector may depend on ambient state.

- **Time** is injected. `manifest.verify` carries `nowEpochMs`; `protocol.decode-payment-required`
  carries `clockEpochMs`, which is what makes `receivedAt` reproducible.
- **Hashes** are computed from the fixture's own bytes:
  - `headerHash` = `sha256:` + hex SHA-256 of the raw `PAYMENT-REQUIRED` header value, as
    received, _before_ base64 decoding.
  - `rawHash` = `sha256:` + hex SHA-256 of the canonical JSON (ADR-012) of the **upstream**
    requirement object — `{scheme, network, asset, amount, payTo, maxTimeoutSeconds, extra}`,
    not the normalized form. It binds to what the merchant actually sent.
- **Failure reasons** are compared, not just failure. Two implementations that reject the
  same input for different reasons have not agreed on anything useful.

### One hazard worth knowing

A JSON _text_ containing `1.0` parses to the integer `1` in JavaScript and to the float
`1.0` in Python. The two would then canonicalize differently — or rather, one would
canonicalize and the other would be rejected.

This cannot arise in a manifest, because the manifest schema forbids fractional numbers
outright and the canonicalizer rejects them anyway. It is called out here so that nobody
adds a fixture containing `X.0` and spends an afternoon on the resulting cross-language
disagreement.

## Generated boundary vectors

The oversized-header vector stores a compact `generatedHeader` recipe instead of roughly
87 KiB of base64. Both runners materialize `decodedBytes` ASCII `x` bytes and standard-base64
encode them before invoking the decoder. This pins the 64 KiB SEC-006 boundary without making a
machine-generated blob part of code review.

## Frozen at M6 (2026-08-03)

The TypeScript reference implementation is feature-complete for v0.1, and **this fixture set
is frozen against it**: 73 vectors across M0–M6 — 65 at the freeze, plus the two ADR-016
added at S15b and the six `policy.host-normalization` vectors added at S17. The gaps recorded here after M1 — route ordering, ledger arithmetic, and
request-fingerprint goldens — are all closed.

Frozen means the Python SDK is written to pass these files as they stand, at S9 and S10.
It does not mean the set can never grow; it means a change to an existing vector is a change
to the contract, not a fix to a test:

- **Adding** a vector is ordinary work. It must cite a SPEC clause and must pass in both
  languages before it lands.
- **Changing or removing** one requires the same justification as changing SPEC itself. A
  vector that Python cannot pass is evidence of a defect in Python, in TypeScript, or in the
  vector's reading of SPEC — and which of the three it is has to be established before any
  file is edited. Editing the fixture first is how a cross-language contract quietly becomes
  a record of whatever the two implementations happen to do.
- Every `id` is permanent. Renaming one breaks the references in `PLAN.md` and in the
  release notes.

The one thing the frozen set deliberately does **not** cover is the request loop itself.
Vectors are pure functions of their inputs, and `client.fetch` is a state machine over a
network; the loop is pinned by each language's own integration suite against the shared test
merchant (`tools/test-merchant`), which is why the merchant's scenario catalogue is a fixture
in its own right.
