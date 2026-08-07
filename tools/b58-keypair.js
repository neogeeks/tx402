/**
 * Convert a base58 Solana secret key into the 64-byte JSON array the live suite reads.
 *
 * Wallets and `solana-keygen` show base58; `createKeyPairSignerFromBytes` takes bytes. That
 * mismatch is one of the three silent-skip traps recorded as PLAN.md open item O33.
 *
 * Input arrives through `TX402_B58_IN` rather than argv so the key never appears in `ps`.
 * Output is the array only, so the caller can capture it with `$(...)` without it reaching
 * a terminal. Deliberately dependency-free: this runs before any install step, and a key
 * converter is the last place to want a supply chain.
 */

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const INDEX = new Map([...ALPHABET].map((character, i) => [character, i]));

/** Big-endian base58 decode. Each leading "1" is one leading zero byte, by definition. */
function decodeBase58(text) {
  const bytes = [0];

  for (const character of text) {
    const value = INDEX.get(character);
    if (value === undefined) {
      throw new Error(`not base58: unexpected character ${JSON.stringify(character)}`);
    }
    let carry = value;
    for (let i = 0; i < bytes.length; i += 1) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  for (const character of text) {
    if (character !== "1") break;
    bytes.push(0);
  }

  return Uint8Array.from(bytes.reverse());
}

const input = (process.env.TX402_B58_IN ?? "").trim();
if (input === "") {
  process.stderr.write("tools/b58-keypair.js: set TX402_B58_IN to a base58 secret key\n");
  process.exit(2);
}

let decoded;
try {
  decoded = decodeBase58(input);
} catch (error) {
  process.stderr.write(`tools/b58-keypair.js: ${error.message}\n`);
  process.exit(2);
}

// A 32-byte value is a seed or a public key, not a keypair, and would fail later inside the
// signer with a much less obvious message. Reject it here where the cause is still visible.
if (decoded.length !== 64) {
  process.stderr.write(
    `tools/b58-keypair.js: decoded ${decoded.length} bytes, expected 64 ` +
      "(a Solana keypair is 32 secret + 32 public)\n",
  );
  process.exit(2);
}

process.stdout.write(JSON.stringify(Array.from(decoded)));
