# Contributing to tx402

Thanks for wanting to help. This document is how the project works — how it is built, what
gets a change merged, and what gets one sent back.

**If you are reporting a security vulnerability, stop and read [`SECURITY.md`](SECURITY.md)
instead.** Do not open a public issue.

## The three rules that shape everything

Understanding these will save you a rejected PR.

### 1. Behaviour is defined by the docs and the conformance vectors

The [documentation](https://docs.tx402.io) states what tx402 guarantees, and the frozen
conformance vectors in `core-spec/` pin those guarantees in executable form. A change that
alters a documented guarantee — a MUST or a MUST NOT — is a contract change, not a bug fix:
open an issue to discuss it first, and land it in the docs and the vectors together with the
code. Reversing an earlier decision is fine; doing it silently is not.

### 2. The conformance fixtures are frozen

`core-spec/conformance/` holds 73 vectors that both SDKs execute. They are the contract that
keeps TypeScript and Python identical.

**Adding** a vector is ordinary work. **Changing or removing** one is a contract change.

If a run disagrees with a frozen vector, establish whether the defect is in TypeScript, in
Python, or in the vector's reading of the intended behaviour **before editing anything**. Editing the fixture
first is exactly how a cross-language contract quietly becomes a record of whatever the two
implementations happen to do. This has caught real bugs — four Python client behaviours were
wrong and the fixtures were right. Rules and rationale: `core-spec/conformance/README.md`.

### 3. Behavioural changes land in both languages, together

TypeScript is the reference implementation, but a merged change that leaves Python behind breaks
the parity the fixtures exist to hold. One PR, both languages, or an explicit issue explaining
why not.

## Getting set up

```bash
git clone https://github.com/neogeeks/tx402.git
cd tx402

# TypeScript — Node 22.12+ to develop
pnpm install
pnpm build

# Python — 3.10+
cd packages/tx402-python && uv sync --all-extras
```

**Two runtimes, and they are not the same number.** The published SDK supports **Node
20.19+**, and CI runs the whole TypeScript suite on Node 20 as well as 22 to keep that
claim true. The _workspace_ needs **Node 22.12+**, because `pnpm check` builds the
documentation site and Astro requires it. `pnpm toolchain:check` — the first thing
`pnpm check` runs — reports the mismatch in a second rather than letting you discover it
after twelve minutes of green checks, and it derives both floors from the manifests instead
of from this paragraph.

## Before you open a PR

Everything below must pass. CI runs all of it across Node 20/22 and CPython 3.10–3.13.

```bash
# TypeScript
pnpm toolchain:check      # the runtime contract: workspace vs. published SDK
pnpm lint                 # eslint, --max-warnings 0
pnpm format:check         # prettier
pnpm typecheck            # tsc, strict + noUncheckedIndexedAccess + exactOptionalPropertyTypes
pnpm test                 # vitest, 90 % coverage gate
pnpm build && pnpm size   # the bundle-size gate
pnpm conformance:check    # fixture index integrity
pnpm manifest:verify      # manifest signature
pnpm docs:check           # generated docs pages are current

# Python
cd packages/tx402-python
uv run ruff check . && uv run ruff format --check .
uv run mypy               # strict
uv run pytest             # 90 % coverage gate
```

### Coverage is a gate, not a report

90 % of statements and branches, enforced in `vitest.config.ts` and in
`[tool.coverage.report] fail_under`. It covers the chain adapters and the CLI too, because those
hold security-critical assertions and exempting them would exempt exactly the code that most
needs the coverage.

## Things that will get a PR sent back

- **A JS `number` or a Python `float` anywhere near money.** Every amount is an integer count of
  atomic units, end to end.
- **A signer call before policy and reservation.** Policy evaluation and budget reservation come
  first, on every attempt, not only the first.
- **A signature, key, or authorization payload reachable from a log, an error, or a
  diagnostic event.**
- **A private key accepted anywhere in the main configuration**, or any CLI flag that could
  carry one.
- **A chain library imported from the core path.** `viem`, `@solana/kit`, `solders`, and the
  upstream scheme packages are reached lazily. A package-contract test asserts this in both
  languages.
- **A deadline built from composed cancellation.** Deadlines are enforced by racing in tx402's
  own control flow. A composed `AbortSignal` was garbage-collected before firing and hung a paid
  retry forever; a rebuilt `Request` silently broke the follow chain. Both were production bugs.
  Cancellation is requested as a courtesy, never trusted.
- **A hand-edit to a generated file.** `bundled-manifest.ts`, `bundled_manifest.py`,
  `conformance/index.json`, and the generated docs pages are emitted by tools and have tests
  asserting they still match their source.
- **A raw NUL byte in a source file.** Write `\u0000`. A file containing a literal NUL is
  classified as binary by git, which means it cannot be diffed and `grep` refuses to search it —
  a source file that cannot be reviewed. CI checks for this.

## Tests

Write the test that would have caught the bug, not the test that passes.

- **Prove the negative.** "`--dry-run` never signs" is a signature **count of zero**, not an
  absence of an assertion. "Nothing is logged" is a search for a seeded secret across the whole
  serialised output.
- **Do not let the harness break what it measures.** A test transport must forward `init` by
  identity; rebuilding an outbound request drops the deadline signal, and against a stub that
  never answers that is not a slow test, it is no deadline at all.
- **Validate the output, not the builder.** A validator that reads the builder's own objects
  agrees with a construction bug instead of catching it. Decode the serialized form.
- **Watch for timing-derived assertions.** Health scores and observed latencies are fresh
  wall-clock measurements. A test that expects a stable outcome from two candidates tying on
  everything above them is asserting something the spec does not promise, and it will flake
  under coverage.

## Commits and PRs

- Conventional commits: `feat(scope):`, `fix(scope):`, `docs(scope):`, `chore(scope):`.
- The subject line says what changed; the body says **why**, and what you considered instead.
- One logical change per PR. A refactor and a behaviour change in one diff cannot be reviewed.
- Reference the docs section, issue, or test ID your change relates to.

## Documentation

The docs site lives in [`docs/`](docs/) and is MDX rendered by Astro Starlight.

```bash
pnpm --filter tx402-docs dev
```

Two pages — `reference/errors.mdx` and `reference/api-typescript.mdx` — are **generated** from
shipped source by `pnpm docs:generate`. Do not hand-edit them: the error table is emitted from
the real taxonomy and the real exit-code map, so a documented code cannot drift from the one the
binary returns. `pnpm docs:check` fails if they are stale.

## Code of conduct

Be decent. Assume the other person is trying to help. Technical disagreement is welcome and
personal attacks are not; maintainers will act on the latter.

## Licence

Contributions are licensed under Apache-2.0, matching the project.
