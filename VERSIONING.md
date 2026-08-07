# Versioning and Release Policy

This document is the compatibility contract between tx402 and the code that depends on it.

## Semantic versioning, and what 0.x actually means

tx402 follows [Semantic Versioning 2.0.0](https://semver.org/). The 0.x caveat is where most
projects get vague, so it is stated explicitly here:

**During 0.x, a minor version may break you.** That is what SemVer permits and it is what tx402
will use when the design demands it. What tx402 additionally commits to is that
**every break is named in the release notes**, in a `### Breaking` section, with the reason and the
migration. A break you have to discover from a stack trace is a defect in the release, not a
consequence of being pre-1.0.

After 1.0, the ordinary rules apply without the caveat: anything in the "breaking" list below
requires a major version.

## The two package names move together

`tx402` on [npm](https://www.npmjs.com/package/tx402) and `tx402` on
[PyPI](https://pypi.org/project/tx402/) are **released at the same version, from the same commit,
at the same time.** They are one product in two languages, held to identical behaviour by 73 shared
conformance vectors, and a version number that meant different things in the two ecosystems would
make that guarantee unreadable.

There is no such thing as a TypeScript-only or Python-only release.

## What counts as a break

Per SPEC §15, each of these requires a major version after 1.0, and a named `### Breaking` entry
during 0.x:

- **Removing or narrowing an exported type**, function, class, or subpath export / extra.
- **Changing an error code**, or changing which code a given situation produces. The SPEC §8
  taxonomy is fifteen codes and adding a sixteenth is itself a break, because callers exhaustively
  match on it.
- **Changing a CLI exit code**, or which situation produces it. `if [ $? -eq 3 ]` in someone's
  shell script is a public API in both languages, and is pinned by a test that holds Python to
  TypeScript's table row for row.
- **Relaxing a default policy.** Making tx402 spend in a situation where the previous version would
  have refused is a break even though nothing in the type signature changed. Tightening a default
  is also a break, but a safer one; it is still named.
- **Changing wire behaviour** — what goes into `PAYMENT-SIGNATURE`, how a challenge is normalized,
  or the route a given set of inputs selects.

Explicitly **not** breaking:

- Adding an export, an option with a safe default, a CLI flag, or a conformance vector.
- Improving an error _message_. The code is the contract; the prose is not.
- Performance changes that keep the gates in SPEC §12.3.

## Release types

| Change                                                             | Version                                      | Notes                                                                                                             |
| ------------------------------------------------------------------ | -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Network or token **manifest update** that changes no API behaviour | **patch**                                    | Re-signing the bundled manifest — including the expiry re-issue due before 2027-08-02 — is a patch.               |
| A **new production network**                                       | **minor**                                    | Requires a chain-adapter security review first. Not optional.                                                     |
| **Protocol dependency upgrade** (`@x402/*`, PyPI `x402`)           | minor, or patch if the envelope is unchanged | Requires replaying **all** conformance fixtures and adding a fixture for every newly accepted envelope or scheme. |
| A **new testnet**                                                  | minor                                        | Testnets are enabled only in explicit test mode (SPEC §16).                                                       |
| Bug fix with no surface change                                     | patch                                        |                                                                                                                   |

## Deprecation

A deprecated API **remains for at least one full minor release** before removal.

Deprecations are surfaced through **types and documentation metadata** — `@deprecated` JSDoc,
`typing.deprecated`, and the API reference. Library code emits **no console warning**, ever. A
dependency that prints to a user's stderr for something the user cannot fix from their own call
site is a dependency that gets vendored around.

## What never happens, at any version

These are architectural, not policy, and no version bump makes them acceptable (SPEC §15, §16):

- No silent fallback from a production network to a testnet.
- No silent fallback from USDC to another asset.
- No silent fallback from a configured external signer to an environment key.
- No bridging, no swapping, no broadcasting the buyer's settlement transaction, no storing private
  keys, and no contact with a tx402-operated backend — because there is not one.

## Supported runtimes

|                   | Supported                                                             |
| ----------------- | --------------------------------------------------------------------- |
| Node.js           | 20 and 22, both in CI                                                 |
| Python            | CPython 3.10, 3.11, 3.12, 3.13, all four in CI                        |
| Operating systems | Linux (full matrix), macOS and Windows (both suites plus a CLI smoke) |

Dropping a runtime that is still upstream-supported is a **minor** during 0.x and a **major**
after 1.0. Adding one is a patch.

## Release process

A release is cut from `main`, by CI, and never from a laptop.

1. Every release gate is green on protected `main`: P0/P1 tests, no
   unresolved critical or high security finding, 100 % TypeScript↔Python conformance parity,
   SBOM + licence check + provenance + reproducible build, the public testnet smoke suite passing
   twice from clean environments, published documentation, and a clear independent security review.
2. `CHANGELOG.md` moves its `Unreleased` section under the new version heading, with any
   `### Breaking` entries written out in full.
3. Both package versions are set to the same number in the same commit.
4. A `v<version>` tag is pushed. That is what triggers the release workflow.
5. CI builds both packages, signs the release manifest with the **release** key — never the
   development key — and publishes to npm and PyPI through **OIDC trusted publishing with
   provenance**. No long-lived registry token exists to be leaked (see `SECURITY.md`).
6. The published artifacts are verified from a clean environment before the release is announced.

Nothing in that sequence can be performed by hand, which is the point: a release that a person
could produce locally is a release whose provenance attestation means nothing.
