# tx402 examples

Four runnable programs, two per language, each written to be read top to bottom. They are the
"runnable versions" the [quickstart](https://docs.tx402.io/start/quickstart/) links to, and they
do the same two things the quickstart does from the CLI.

| File                       | What it does                                                 |
| :------------------------- | :----------------------------------------------------------- |
| `typescript/quickstart.ts` | Pays for one resource and prints the response                |
| `typescript/dry-run.ts`    | Inspects a merchant's terms without a key and without paying |
| `python/quickstart.py`     | The same paid call, in Python                                |
| `python/dry_run.py`        | The same inspection, in Python                               |

## Environment

Every example reads its merchant from one variable:

| Variable                | Required for        | What it is                                               |
| :---------------------- | :------------------ | :------------------------------------------------------- |
| `TX402_MERCHANT_URL`    | all four            | The URL of a resource that answers `402`                 |
| `TX402_DEV_PRIVATE_KEY` | the two quickstarts | A 0x-prefixed 32-byte hex key for a **throwaway** wallet |

The dry-run examples need no key at all — that is the point of them.

```bash
export TX402_MERCHANT_URL=http://127.0.0.1:54321/resource
export TX402_DEV_PRIVATE_KEY=0x...
```

A key in an environment variable is a key any child process can read. That is fine for a
low-balance testnet wallet and wrong for anything else; see
[key management](https://docs.tx402.io/security/keys/) for the real answer.

## Getting a merchant to point at

The quickstart's local test merchant is the easiest one. From the repository root:

```bash
node tools/test-merchant/cli.js \
  --requirements baseSepolia \
  --facilitator https://x402.org/facilitator
```

It prints one JSON line with a `url`; the resource path is `/resource`. With `--facilitator` it
performs a **real settlement**, so testnet USDC actually moves.

These examples accept that merchant over plain HTTP **only because it is on localhost**. The SDK
requires HTTPS everywhere else, and the `allowInsecureLocalhost` / `allow_insecure_localhost`
opt-in each example uses is scoped by the SDK to `localhost`, `127.0.0.1` and `::1` — it cannot
downgrade a real merchant. Each example derives it from the URL rather than hardcoding it, so
copying one of these files into your own project does not carry a relaxation along with it.

## Running them

### TypeScript

```bash
pnpm --filter tx402-example-typescript quickstart
pnpm --filter tx402-example-typescript dry-run
```

**These scripts need Node 22.6 or newer**, because they run `.ts` files directly through
`node --experimental-strip-types`. That is a property of how the _examples_ are run, not of the
package: `tx402` itself supports **Node 20.19+**, which is what the quickstart and the published
`engines` field both state. If you are on Node 20, either upgrade for the examples or use the
CLI, which has no such requirement.

### Python

```bash
python examples/python/quickstart.py
python examples/python/dry_run.py
```

Python 3.10 or newer. The quickstart example needs the EVM extra — `pip install "tx402[evm]"`.

## Testnets have to be asked for by name

Every example names its networks explicitly:

```
allowedNetworks: ["eip155:84532", "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"]
```

tx402's default policy allows only **production** networks. This is deliberate: a
silent fall back from the network you meant to a different one is worse than a refusal, so
it is forbidden outright. The CLI's equivalent is `--network`.
