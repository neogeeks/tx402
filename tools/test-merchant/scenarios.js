/**
 * Scenario catalogue for the deterministic test merchant.
 *
 * Each scenario is a small state machine over attempt numbers rather than a bag of flags,
 * because most of what needs testing is a *sequence*: challenge, then pay, then re-challenge.
 * A flag-based server cannot express "402 on the paid retry, then 200 on the one after".
 *
 * Every scenario maps to something normative. The `covers` field records what, so that a
 * scenario nobody can justify is visible as such.
 */

/**
 * The fee payer the public x402 facilitator publishes on `/supported` for Solana.
 *
 * Solana's fee payer is the *facilitator's*, not the buyer's — that is what keeps the
 * buyer's SOL untouched across a payment. It is a static default here so that the
 * deterministic (no-`--facilitator`) merchant still emits a **plannable** challenge; when
 * `--facilitator` is supplied, `cli.js` re-reads this from `/supported` so a rotated fee
 * payer cannot silently break the documented quickstart.
 */
export const FACILITATOR_FEE_PAYER = "CKPKJWNdJEqa81x7CkZ14BVPiY6y16Sxs7owznqtWYp5";

/**
 * Default requirements offered when a caller does not supply their own.
 *
 * **`extra` is not decoration.** Every entry here must carry what its chain family needs to
 * produce an authorization, because these are the requirement sets the documented
 * quickstart offers a first-time reader: EVM needs the token's EIP-712 domain name and
 * version for EIP-3009, and SVM needs the fee payer that will pay for the transfer. All
 * four shipped `extra: {}` through S16, which made the quickstart's merchant emit a
 * challenge tx402 itself rejects — `eip712-domain-missing` and `svm-feePayer-missing` — so
 * the one command the docs tell a stranger to run could not settle on either chain
 * (PLAN.md O64).
 *
 * That survived every green gate because `tools/ttv`, which measures SPEC §16 and reports
 * PASS, builds its own requirement object and never reads this one. The parity is now
 * pinned by `ux-regressions-s16.test.ts`, which plans directly from these values.
 */
export const DEFAULT_REQUIREMENTS = {
  base: {
    scheme: "exact",
    network: "eip155:8453",
    asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    amount: "50000",
    payTo: "0x1234567890AbcdEF1234567890aBcdef12345678",
    maxTimeoutSeconds: 60,
    // Mainnet USDC's on-chain EIP-712 domain name is "USD Coin"; a mismatch here produces a
    // signature the token rejects on-chain, so the name is per-network rather than shared.
    extra: { name: "USD Coin", version: "2" },
  },
  baseSepolia: {
    scheme: "exact",
    network: "eip155:84532",
    asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    amount: "50000",
    payTo: "0x1234567890AbcdEF1234567890aBcdef12345678",
    maxTimeoutSeconds: 60,
    // Base Sepolia's test USDC uses "USDC". Verified by a real settled payment at S16.
    extra: { name: "USDC", version: "2" },
  },
  solana: {
    scheme: "exact",
    network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    amount: "50000",
    payTo: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
    maxTimeoutSeconds: 60,
    extra: { feePayer: FACILITATOR_FEE_PAYER },
  },
  solanaDevnet: {
    scheme: "exact",
    network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
    asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    amount: "50000",
    payTo: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
    maxTimeoutSeconds: 60,
    extra: { feePayer: FACILITATOR_FEE_PAYER },
  },
};

/**
 * An action the server takes for one request.
 *
 * @typedef {object} Action
 * @property {"challenge"|"deliver"|"malformed-challenge"|"status"|"redirect"|"hang"|"reject"} type
 * @property {number} [status]
 * @property {string} [location]
 * @property {boolean} [omitPaymentResponse]
 * @property {"corrupt"|"unsuccessful"} [paymentResponse] how to spoil PAYMENT-RESPONSE
 * @property {string} [reason]
 */

/**
 * @typedef {object} Scenario
 * @property {string} description
 * @property {string[]} covers  normative clauses or test IDs this scenario exists for
 * @property {(context: {paidAttempt: number, hasSignature: boolean}) => Action} next
 */

/** @type {Record<string, Scenario>} */
export const SCENARIOS = {
  "unpaid-200": {
    description: "Never challenges. The resource is free.",
    covers: ["T-001"],
    next: () => ({ type: "deliver", status: 200, omitPaymentResponse: true }),
  },

  "pay-once": {
    description:
      "Challenges the first request, then delivers once a valid signature arrives.",
    covers: ["T-002", "T-003", "SPEC §6.7"],
    next: ({ hasSignature }) =>
      hasSignature ? { type: "deliver", status: 200 } : { type: "challenge" },
  },

  "always-402": {
    description:
      "Challenges every request, including paid retries, without ever accepting payment.",
    covers: ["SPEC §6.7 maxPaidAttempts"],
    next: () => ({ type: "challenge" }),
  },

  "rechallenge-once": {
    description:
      "Challenges, rejects the first paid attempt with a fresh 402, then accepts the second.",
    covers: ["T-010"],
    next: ({ paidAttempt }) =>
      paidAttempt >= 2 ? { type: "deliver", status: 200 } : { type: "challenge" },
  },

  "rechallenge-malformed": {
    description:
      "Challenges normally, then answers the paid attempt with a 402 whose PAYMENT-REQUIRED " +
      "does not decode. The re-challenge gets the same strict parse the first one did.",
    covers: ["T-010", "SPEC §6.2", "SPEC §6.7"],
    next: ({ hasSignature }) =>
      hasSignature ? { type: "malformed-challenge" } : { type: "challenge" },
  },

  "malformed-challenge": {
    description: "Returns a 402 whose PAYMENT-REQUIRED header is not decodable.",
    covers: ["T-009", "SPEC §6.2"],
    next: () => ({ type: "malformed-challenge" }),
  },

  "missing-payment-response": {
    description:
      "Accepts payment and returns 200 but omits PAYMENT-RESPONSE. Accepted with a warning " +
      "only where the pinned protocol marks it optional (SPEC §6.7).",
    covers: ["SPEC §6.7"],
    next: ({ hasSignature }) =>
      hasSignature
        ? { type: "deliver", status: 200, omitPaymentResponse: true }
        : { type: "challenge" },
  },

  "corrupt-payment-response": {
    description:
      "Answers the paid attempt with 200 and a PAYMENT-RESPONSE header that does not " +
      "decode. A present header the buyer cannot read is evidence in neither direction, so " +
      "the outcome is ambiguous: the resource is *not* delivered, and the reservation is " +
      "retained to its TTL rather than committed or released (ADR-016). Deliberately the " +
      "twin of missing-payment-response, which omits the header entirely and does deliver " +
      "— the pair is what stops 'absent' and 'unparseable' being restated as one another.",
    covers: ["SPEC §6.7", "ADR-016"],
    next: ({ hasSignature }) =>
      hasSignature
        ? { type: "deliver", status: 200, paymentResponse: "corrupt" }
        : { type: "challenge" },
  },

  "unsuccessful-settlement": {
    description:
      "Delivers a 200 whose PAYMENT-RESPONSE reports success:false. A merchant contradicting " +
      "itself is not a payment; the buyer must not commit the spend.",
    covers: ["SPEC §6.7", "SPEC §5.3"],
    next: ({ hasSignature }) =>
      hasSignature
        ? { type: "deliver", status: 200, paymentResponse: "unsuccessful" }
        : { type: "challenge" },
  },

  "error-after-signature": {
    description:
      "Challenges, then returns 503 to the paid retry. The signature was transmitted, so the " +
      "outcome is ambiguous and the reservation must be retained.",
    covers: ["T-011", "SPEC §6.7"],
    next: ({ hasSignature }) =>
      hasSignature ? { type: "status", status: 503 } : { type: "challenge" },
  },

  "refused-after-signature": {
    description:
      "Challenges, then answers the paid retry with 403. The merchant refused the request " +
      "outright rather than failing to complete it, so no settlement exists and the buyer's " +
      "reservation must be released rather than retained.",
    covers: ["SPEC §6.7", "SPEC §5.3"],
    next: ({ hasSignature }) =>
      hasSignature ? { type: "status", status: 403 } : { type: "challenge" },
  },

  "settled-but-refused": {
    description:
      "Challenges, then answers the paid retry with 403 *and* a successful PAYMENT-RESPONSE. " +
      "The merchant took the money and could not hand over the resource. SPEC §5.3 requires " +
      "the spend to stay committed and ResourceDeliveryError with paid=true; releasing here " +
      "hands back budget for money that moved. Deliberately the twin of " +
      "refused-after-signature, which sends the same 403 with no settlement claim and must " +
      "release — the pair is what stops either behaviour being restated as the other.",
    covers: ["SPEC §5.3", "SPEC §6.7"],
    next: ({ hasSignature }) =>
      hasSignature ? { type: "deliver", status: 403 } : { type: "challenge" },
  },

  "settled-but-rechallenged": {
    description:
      "Challenges, then answers the paid retry with 402 *and* a successful PAYMENT-RESPONSE. " +
      "A merchant contradicting itself, and the most expensive case to get wrong: a bare 402 " +
      "is the one outcome strong enough to release and re-sign, so obeying the status line " +
      "here pays twice for one resource.",
    covers: ["SPEC §5.3", "SPEC §6.7"],
    next: ({ hasSignature }) =>
      hasSignature ? { type: "deliver", status: 402 } : { type: "challenge" },
  },

  "hang-after-signature": {
    description:
      "Challenges, then never responds to the paid retry. Same ambiguity as a 5xx, reached " +
      "through a timeout instead.",
    covers: ["T-011"],
    next: ({ hasSignature }) => (hasSignature ? { type: "hang" } : { type: "challenge" }),
  },

  "cross-origin-redirect": {
    description:
      "Challenges, then answers the paid retry with a 307 to a different origin. Must be " +
      "blocked before the signature is transmitted onward.",
    covers: ["T-012", "SEC-005"],
    next: ({ hasSignature }) =>
      hasSignature
        ? { type: "redirect", status: 307, location: "https://elsewhere.example.net/paid" }
        : { type: "challenge" },
  },

  "same-origin-redirect": {
    description:
      "Challenges, then answers the paid retry with a same-origin 307. Permitted — the " +
      "counterpart to cross-origin-redirect, so the block is provably not blanket.",
    covers: ["SEC-005", "SPEC §6.1"],
    next: ({ hasSignature }) =>
      hasSignature
        ? { type: "redirect", status: 307, location: "/delivered" }
        : { type: "challenge" },
  },

  "server-error": {
    description: "Returns 500 to the very first request, before any challenge is issued.",
    covers: ["T-017"],
    next: () => ({ type: "status", status: 500 }),
  },
};

/** @param {string} name */
export function requireScenario(name) {
  const scenario = SCENARIOS[name];
  if (!scenario) {
    throw new Error(
      `Unknown scenario ${JSON.stringify(name)}. Known: ${Object.keys(SCENARIOS).join(", ")}`,
    );
  }
  return scenario;
}
