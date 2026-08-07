/**
 * Optional private-key convenience signer adapters.
 *
 * Deliberately isolated behind the `tx402/signers` subpath export. Per SEC-001 the primary
 * client configuration accepts **signer abstractions only** and never a raw private key
 * string, so nothing in the core API can reach this module: a caller has to import it by
 * name, which is what makes the choice explicit and auditable in a diff.
 *
 * **Use an external signer if you can.** SPEC §9.1 lists prompt injection extracting a wallet
 * key as a live threat for exactly the autonomous agents this SDK targets, and a key held in
 * process memory is a key an in-process compromise can read. A KMS, a hardware wallet, or a
 * remote signing service implements the same {@link EvmSigner} interface and keeps the key
 * outside the blast radius. This adapter exists for development and for small, dedicated,
 * low-balance wallets.
 *
 * The key is captured in a closure and is never stored on the returned object, never
 * serialized, and never logged. `toJSON` and Node's inspection hook are both overridden so
 * that a signer accidentally passed to a logger renders as a redacted placeholder rather
 * than as an object graph containing the account.
 *
 * @example
 * ```ts
 * import { keypairToSolanaSigner, privateKeyToEvmSigner } from "tx402/signers";
 *
 * const evm = privateKeyToEvmSigner(process.env.TX402_DEV_PRIVATE_KEY as `0x${string}`);
 * const solana = await keypairToSolanaSigner(process.env.TX402_DEV_SOLANA_KEYPAIR!);
 * ```
 */

import { privateKeyToAccount } from "viem/accounts";

import type {
  EvmSigner,
  EvmTypedDataRequest,
  SolanaSigner,
  SolanaSignRequest,
} from "../core/signers.js";

const PRIVATE_KEY_PATTERN = /^0x[0-9a-fA-F]{64}$/u;

/** Bytes in a Solana keypair file: 32-byte seed followed by the 32-byte public key. */
const SOLANA_KEYPAIR_BYTES = 64;

/** A signer with the key material redacted from every serialization path. */
export interface RedactedSigner {
  toJSON(): { readonly kind: string; readonly address: string };
}

/**
 * Wraps a raw secp256k1 private key as an {@link EvmSigner}.
 *
 * @param privateKey 32-byte hex, `0x`-prefixed. Never logged, and rejected before viem sees
 *                   it if it is malformed — a validation error from a chain library tends to
 *                   quote its input.
 */
export function privateKeyToEvmSigner(
  privateKey: `0x${string}`,
): EvmSigner & RedactedSigner {
  if (typeof privateKey !== "string" || !PRIVATE_KEY_PATTERN.test(privateKey)) {
    throw new TypeError(
      "privateKeyToEvmSigner expects a 0x-prefixed 32-byte hex private key",
    );
  }

  const account = privateKeyToAccount(privateKey);
  const address = account.address;

  const signer: EvmSigner & RedactedSigner = {
    kind: "evm",
    getAddress: () => Promise.resolve(address),
    signTypedData: (request: EvmTypedDataRequest) =>
      // `presentation` is tx402's human-readable summary (SPEC §6.6). viem signs the EIP-712
      // structure only, so it is deliberately not forwarded.
      account.signTypedData({
        domain: request.domain,
        types: request.types,
        primaryType: request.primaryType,
        message: request.message,
      } as Parameters<typeof account.signTypedData>[0]),
    toJSON: () => ({ kind: "evm", address }),
  };

  Object.defineProperty(signer, "address", { value: address, enumerable: true });
  Object.defineProperty(signer, Symbol.for("nodejs.util.inspect.custom"), {
    value: () => `EvmSigner(evm:${address})`,
    enumerable: false,
  });

  return Object.freeze(signer);
}

/**
 * Normalizes the three shapes a Solana keypair arrives in into its 64 raw bytes.
 *
 * `solana-keygen` writes a JSON array of byte values to `~/.config/solana/id.json`, so that
 * string is what a caller actually has in hand and what an environment variable actually
 * carries. Accepting it here rather than making every call site parse it is what keeps the
 * parsing — and therefore the mistakes — in one place.
 *
 * Errors never quote the input. A malformed key is still a key, and a validation message
 * that echoes it is how key material reaches a log or a traceback.
 */
function toSolanaKeypairBytes(
  keypair: string | Uint8Array | readonly number[],
): Uint8Array {
  let values: Uint8Array | readonly number[];

  if (typeof keypair === "string") {
    let parsed: unknown;
    try {
      parsed = JSON.parse(keypair);
    } catch {
      throw new TypeError(
        "keypairToSolanaSigner expects a JSON array of 64 keypair bytes, as written by " +
          "`solana-keygen` — it could not be parsed as JSON",
      );
    }
    if (!Array.isArray(parsed)) {
      throw new TypeError("keypairToSolanaSigner expects a JSON array of 64 keypair bytes");
    }
    values = parsed as readonly number[];
  } else if (keypair instanceof Uint8Array || Array.isArray(keypair)) {
    values = keypair;
  } else {
    // Reached when a caller passes `process.env.SOMETHING` that is not set. Without this
    // branch the length check below throws a bare "cannot read properties of undefined",
    // which says nothing about what was expected.
    throw new TypeError(
      "keypairToSolanaSigner expects 64 keypair bytes or the JSON array string " +
        "`solana-keygen` writes, and received neither",
    );
  }

  if (values.length !== SOLANA_KEYPAIR_BYTES) {
    throw new TypeError(
      `keypairToSolanaSigner expects ${String(SOLANA_KEYPAIR_BYTES)} keypair bytes, ` +
        `received ${String(values.length)}`,
    );
  }

  const bytes = values instanceof Uint8Array ? values : Uint8Array.from(values);
  // `Uint8Array.from` silently coerces a non-integer or out-of-range entry, so the check has
  // to happen against the source values rather than against the result.
  if (
    !(values instanceof Uint8Array) &&
    !values.every((value) => Number.isInteger(value) && value >= 0 && value <= 255)
  ) {
    throw new TypeError("keypairToSolanaSigner expects keypair bytes in the range 0–255");
  }

  return bytes;
}

/**
 * Wraps a raw Ed25519 keypair as a {@link SolanaSigner}.
 *
 * The Solana counterpart to {@link privateKeyToEvmSigner}, and it carries the same warning:
 * prefer an external signer. It is `async` because `@solana/kit` is loaded lazily — this
 * module is reachable by anyone who installed only the EVM dependencies, and a top-level
 * `@solana/kit` import would break `privateKeyToEvmSigner` for them.
 *
 * @param keypair The 64 bytes of a Solana keypair, or the JSON array string that
 *                `solana-keygen` writes. Never logged, and rejected before `@solana/kit`
 *                sees it if it is malformed.
 */
export async function keypairToSolanaSigner(
  keypair: string | Uint8Array | readonly number[],
): Promise<SolanaSigner & RedactedSigner> {
  const bytes = toSolanaKeypairBytes(keypair);

  const { createKeyPairSignerFromBytes, createSignableMessage } =
    await import("@solana/kit");
  const inner = await createKeyPairSignerFromBytes(bytes);
  const address = inner.address.toString();

  const signer: SolanaSigner & RedactedSigner = {
    kind: "solana",
    getPublicKey: () => Promise.resolve(address),
    signTransaction: async (request: SolanaSignRequest) => {
      // Only `messageBytes` is signed. `transactionBytes` and `presentation` exist so a
      // hardware or KMS adapter can display and independently decode the same transaction;
      // forwarding them here would sign something other than what the runtime verifies.
      const [signatures] = await inner.signMessages([
        createSignableMessage(request.messageBytes),
      ]);
      const signature = signatures?.[inner.address];
      if (signature === undefined) {
        throw new Error("keypairToSolanaSigner produced no signature");
      }
      return new Uint8Array(signature);
    },
    toJSON: () => ({ kind: "solana", address }),
  };

  Object.defineProperty(signer, "address", { value: address, enumerable: true });
  Object.defineProperty(signer, Symbol.for("nodejs.util.inspect.custom"), {
    value: () => `SolanaSigner(solana:${address})`,
    enumerable: false,
  });

  return Object.freeze(signer);
}
