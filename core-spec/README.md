# core-spec

Language-neutral artifacts shared by both SDKs. Nothing here is TypeScript- or Python-specific, and
neither implementation may keep a private copy of any of it.

| Directory      | Contents                                                                         |
| :------------- | :------------------------------------------------------------------------------- |
| `schemas/`     | JSON Schema 2020-12 for every tx402 internal data shape (SPEC §5)                |
| `conformance/` | Test vectors both SDKs are validated against (ADR-005), plus the runner contract |
| `manifests/`   | The signed release manifest and the trusted signing public key (SPEC §5.4)       |

## What is frozen

The following were frozen at **M0** (session S2) and are the last cheap moment to rename anything:

- every field name in `schemas/`
- the fifteen error codes and fifteen error class names in `schemas/common.schema.json`
- the canonical serialization used for manifest signing (ADR-012)
- the conformance vector format and vector IDs

Changing any of them after M0 is a wire-visible or API-visible break and follows SPEC §15: during
`0.x`, release notes must call it out explicitly; after `1.0` it requires a major version.

## Schemas

`$id`s are stable URLs under `https://tx402.dev/schemas/v1/`. They are identifiers, not fetch
targets — every runner resolves them from this directory offline. Cross-file `$ref`s are by `$id`,
so both `ajv` (TypeScript) and `jsonschema` (Python) need all six files registered before use; the
conformance runners do this.

| File                                      | SPEC reference | Notes                                                     |
| :---------------------------------------- | :------------- | :-------------------------------------------------------- |
| `common.schema.json`                      | §5, §8         | Shared primitives: CAIP-2/19, atomic amounts, error enums |
| `normalized-payment-required.schema.json` | §5.1           | tx402's internal form, not the wire format                |
| `route-candidate.schema.json`             | §5.2           | Includes non-viable candidates and their reasons          |
| `spend-reservation.schema.json`           | §5.3           | 120 s TTL, four states                                    |
| `spend-entry.schema.json`                 | §5.3           | Committed spend, rolling 3 600 000 ms window              |
| `release-manifest.schema.json`            | §5.4           | Canonical CAIP-2 keys plus the alias map (ADR-010)        |
| `conformance-vector.schema.json`          | ADR-005        | The fixture format itself                                 |

### Why the normalized schemas are not the wire format

SPEC §5 is explicit that its schemas are tx402's _internal normalized_ representation. The actual v2
envelope comes from the pinned `@x402/core`, where the fields are named differently — `accepts[]`
rather than `requirements[]`, `amount` rather than `amountAtomic`, and there is no `method` on
`resource` at all. ADR-010 records the mapping. It happens once, in the decoder, and nowhere else.

## Integer-only money

Every amount in every schema here is a **string** matching `^(0|[1-9][0-9]*)$` or
`^[1-9][0-9]*$`. No amount is ever a JSON number. This is ADR-006, and it is enforced at the schema
level precisely because a JSON number would survive a round-trip through both languages while
quietly losing precision above 2^53.
