# Security Policy

`tx402` signs payment authorizations on behalf of software that often runs unattended. We take
reports seriously and we would rather hear about something uncertain than not hear about it.

## Reporting a vulnerability

**Use GitHub Private Vulnerability Reporting:**

👉 **https://github.com/neogeeks/tx402/security/advisories/new**

Please **do not** open a public issue, pull request, or discussion for a security problem. A
public report is a disclosure, and it starts a clock for every user of the package before there
is anything for them to upgrade to.

Private reporting gives us a confidential thread, lets us credit you in the advisory, and lets
us request a CVE when one is warranted. You do not need a special relationship with the project
to use it — the button is open to anyone with a GitHub account.

### What to include

Whatever you have. A partial report is worth sending.

- What you were able to do that you should not have been able to do.
- The version, language (TypeScript or Python), and environment.
- A reproduction — a script, a test case, or a sequence of steps.
- The impact as you see it, especially whether it can move funds.

If you cannot get a full reproduction, send the observation anyway and say so.

### What to expect

| When            | What                                                                    |
| --------------- | ----------------------------------------------------------------------- |
| Within 48 hours | Acknowledgement that a human has read it                                |
| Within 7 days   | An initial assessment: whether we can reproduce it, and a severity      |
| Ongoing         | Progress updates at least every 7 days while it is open                 |
| On fix          | A release, a published advisory, and credit unless you prefer otherwise |

We ask for a **90-day** coordinated disclosure window, and will move faster than that for
anything actively exploitable. If we are not responding, escalate by opening a public issue that
says only that you have an unanswered private report — no details.

## Scope

### In scope

Anything that lets an attacker cause tx402 to:

- produce a signature the caller's policy should have refused;
- exceed a configured `maxPerRequest` or `maxPerHour` cap;
- transmit an authorization to an origin the caller did not intend;
- leak a private key, a signature, or an authorization payload into logs, errors, or diagnostics;
- accept a tampered release manifest, or route a payment to an asset or contract the signed
  manifest does not declare;
- crash, hang indefinitely, or consume unbounded memory on a malformed `PAYMENT-REQUIRED`
  challenge;
- report a settled payment as unsettled, or an unsettled one as settled;
- bypass the rule that policy evaluation and budget reservation precede every signer call.

Reports about the **CLI** are in scope on the same terms, particularly anything that puts key
material into a command line, an environment dump, or a log.

### Out of scope

- **Vulnerabilities in dependencies**, unless tx402's use of them is what creates the exposure.
  Report those upstream; tell us too if tx402 needs to pin around it.
- **A merchant charging for something worthless.** tx402 enforces your caps and the protocol's
  rules; it cannot judge value.
- **Key compromise through your own process.** A key you hand to `tx402/signers` lives in your
  process memory. That is documented, and the mitigation is an external signer.
- **Missing hardening that has no exploit path.** Interesting, and better as an issue.
- Automated scanner output without a demonstrated impact.

## What tx402 already guarantees

These are tested properties, not aspirations. A report that one of them does not hold is a
serious report:

- Policy evaluation and an atomic budget reservation complete **before** any signer call, on
  every attempt (SEC-002).
- Signatures, private keys, complete signed transactions, and authorization payloads never enter
  the diagnostic stream, an error's serialization, or a log (SEC-003). The test suite seeds real
  secrets into every input and searches the whole output for each one.
- The main configuration accepts signer **abstractions**, never a raw private key. The
  convenience adapter is isolated behind its own import path (SEC-001).
- A paid retry never follows a cross-origin redirect, and fails before transmitting the
  signature (SEC-005). It does not follow same-origin ones either — see ADR-014.
- Challenge parsing enforces byte, depth, array, and string limits (SEC-006).
- The bundled release manifest is Ed25519-signed and verified offline at client construction
  against keys compiled into the package (SEC-007).
- Every amount is an integer in atomic units, everywhere, in both languages (ADR-006).
- The core import path loads no chain library in either language.

## Supported versions

| Version | Supported                                   |
| ------- | ------------------------------------------- |
| `0.1.x` | ✅                                          |
| `0.0.x` | ❌ — placeholder releases, never functional |

Until `1.0`, security fixes land on the latest minor only.

## Our own practices

- Releases are published from CI with provenance, through trusted publishing. No long-lived
  registry token exists.
- The release manifest signing key is held outside developer machines.
- Every dependency bump replays all 73 cross-language conformance vectors before it ships.
- Both SDKs are held to the same behavioural fixtures, so a fix that lands in one language and
  not the other fails CI rather than shipping.

Thank you for helping keep tx402 safe.
