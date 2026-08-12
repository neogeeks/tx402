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
at the same time.** They are one product in two languages, held to identical behaviour by 88 shared
conformance vectors, and a version number that meant different things in the two ecosystems would
make that guarantee unreadable.

There is no such thing as a TypeScript-only or Python-only release.

## What counts as a break

Per SPEC §15, each of these requires a major version after 1.0, and a named `### Breaking` entry
during 0.x:

- **Removing or narrowing an exported type**, function, class, or subpath export / extra.
- **Changing an error code**, or changing which code a given situation produces. The SPEC §8
  taxonomy is seventeen codes and adding an eighteenth is itself a break, because callers exhaustively
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

A release is cut from `main`, by CI, and never from a laptop. What CI does with the tag is
**verify and publish** — it does not sign. The one artifact that cannot be produced in CI is the
release-key signature on the bundled manifest, precisely because a key CI could use to sign is a
key CI could be tricked into signing with; so the manifest is signed **before** the tag exists and
CI refuses a tag whose manifest is signed by anything else. The authoritative description of the
workflow is [`.github/workflows/release.yml`](.github/workflows/release.yml); this is what it does,
in order.

**Prepared in one commit on `main`, before the tag:**

1. Every release gate is green on protected `main`: P0/P1 tests, no unresolved critical or high
   security finding, 100 % TypeScript↔Python conformance parity, SBOM, licence check, provenance,
   and reproducible build, the public testnet smoke suite passing twice from clean environments,
   published documentation, and a clear independent security review.
2. `CHANGELOG.md` moves its `Unreleased` section under the new version heading, with any
   `### Breaking` entries written out in full.
3. Both package versions — and the two generated CLI version modules — are set to the same number
   in the same commit. `node tools/version-sync/index.js check` holds all four in lockstep, and the
   tag is folded into the same check at release time.
4. The bundled manifest is regenerated and **signed with the release key — never the development
   key `tx402-release-1`** — and embedded. Signing happens here, on a machine that holds the key,
   not in CI. `pnpm manifest:verify` confirms it locally. The signing-key rotation procedure is in
   [the manifest runbook](docs/src/content/docs/operations/release-manifest.mdx).

**Triggered by the tag:**

5. A `v<version>` tag is pushed. That, and nothing else, triggers `release.yml`.
6. The release gates re-run _on the tagged commit_ — a green CI run on `main` is not evidence about a
   tag, since a tag need not point at the commit that was tested. The **verify** job first proves the
   tagged commit is **contained in protected `main`** (`git merge-base --is-ancestor`), so a release
   can never be cut from untested or force-pushed history; then it runs the aggregate `pnpm check`,
   the measured release gates (`fuzz`, `adversarial`, `perf`, `supply-chain`, `reproducible`), the
   Python suite, checks that the tag matches every declared version, packs and imports every
   documented install, and **verifies the embedded manifest is signed by the release key** (it reads
   the manifest's `signature.keyId` and fails outright if it is `tx402-release-1`). The
   **durable-store**, **durable-object**, and **gateway-golden** jobs re-run the Redis, Durable
   Object, and capability-gateway suites on the same tagged commit — `pnpm check` does not include
   them, so they are their own jobs. Every one of these is a `needs:` of both publish jobs, so a tag
   cannot publish without proving them (`tools/workflow-lint` fails the file if a publish job drops
   the dependency). CI verifies the signature; it never creates one.
7. The **docs-published** job probes the live documentation site and requires every page to return
   `200` before either registry is touched. Both publish jobs `needs:` it, so a stale or dead site
   stops the release with nothing published.
8. The **npm** and **pypi** jobs publish through **OIDC trusted publishing with provenance**.
   Neither job holds a registry token — no long-lived registry credential exists to be leaked; the
   workflow's own identity is exchanged for a short-lived one at publish time (see `SECURITY.md`).
9. The **smoke** job installs both packages from the registries into clean environments, runs each
   CLI, imports every advertised entry point, and asserts npm recorded a provenance attestation —
   the only check that verifies the registry rather than the repository.

Nothing in the tag-triggered sequence can be performed by hand, which is the point: a release that
a person could produce locally is a release whose provenance attestation means nothing. The one
step a person _does_ perform — signing the manifest with the release key — happens before the tag
and is the one thing CI is built to check rather than to do.
