/** Integer-only public money parsing (ADR-006, SPEC §4.3). */

export interface MoneyAssetMetadata {
  readonly symbol: string;
  readonly decimals: number;
}

export type MoneyParseFailureReason =
  | "number-not-allowed"
  | "expected-string"
  | "invalid-format"
  | "unexpected-symbol"
  | "fractional-precision-exceeded"
  | "amount-must-be-positive";

export class MoneyParseError extends TypeError {
  constructor(
    readonly reason: MoneyParseFailureReason,
    message: string,
  ) {
    super(message);
    this.name = "MoneyParseError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

const MONEY_PATTERN = /^(0|[1-9][0-9]*)(?:\.([0-9]+))? ([A-Z][A-Z0-9]{0,11})$/u;

/**
 * Parse `<decimal> <SYMBOL>` into atomic units without ever passing through a JS number.
 *
 * The textual form is deliberately canonical: one ASCII space, no sign, no exponent, no
 * leading zeroes, and no more fractional digits than the signed manifest declares.
 */
export function parseMoneyAtomic(value: unknown, asset: MoneyAssetMetadata): bigint {
  if (typeof value === "number") {
    throw new MoneyParseError(
      "number-not-allowed",
      "Monetary values must be decimal strings; JavaScript numbers are rejected",
    );
  }
  if (typeof value !== "string") {
    throw new MoneyParseError("expected-string", "Monetary value must be a string");
  }
  if (
    !Number.isInteger(asset.decimals) ||
    asset.decimals < 0 ||
    asset.decimals > 36 ||
    !/^[A-Z][A-Z0-9]{0,11}$/u.test(asset.symbol)
  ) {
    throw new MoneyParseError("invalid-format", "Asset money metadata is invalid");
  }

  const match = MONEY_PATTERN.exec(value);
  if (match === null) {
    throw new MoneyParseError(
      "invalid-format",
      "Money must use canonical `<decimal> <SYMBOL>` syntax",
    );
  }
  const [, whole = "", fraction = "", symbol = ""] = match;
  if (symbol !== asset.symbol) {
    throw new MoneyParseError(
      "unexpected-symbol",
      `Expected ${asset.symbol}, received ${symbol}`,
    );
  }
  if (fraction.length > asset.decimals) {
    throw new MoneyParseError(
      "fractional-precision-exceeded",
      `${asset.symbol} supports at most ${asset.decimals} fractional digits`,
    );
  }

  const atomicText = `${whole}${fraction.padEnd(asset.decimals, "0")}`.replace(
    /^0+(?=\d)/u,
    "",
  );
  if (atomicText.length > 78) {
    throw new MoneyParseError("invalid-format", "Money exceeds 78 atomic digits");
  }
  return BigInt(atomicText || "0");
}

/**
 * Render atomic units back to a canonical decimal string, for human presentation only.
 *
 * SPEC §6.6 requires the request handed to an external signer to carry a decimal amount
 * beside the atomic one, so a hardware wallet can show a person what they are approving.
 * The conversion is pure string arithmetic — a `bigint` never becomes a `number` — and the
 * result round-trips through {@link parseMoneyAtomic} for the same asset.
 */
export function formatMoneyDecimal(atomic: bigint | string, decimals: number): string {
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 36) {
    throw new MoneyParseError("invalid-format", "Asset decimals are invalid");
  }
  const value = typeof atomic === "bigint" ? atomic : BigInt(atomic);
  if (value < 0n) {
    throw new MoneyParseError(
      "amount-must-be-positive",
      "Money amount must not be negative",
    );
  }
  const digits = value.toString().padStart(decimals + 1, "0");
  if (decimals === 0) return digits;
  const whole = digits.slice(0, digits.length - decimals);
  const fraction = digits.slice(digits.length - decimals).replace(/0+$/u, "");
  return fraction.length === 0 ? whole : `${whole}.${fraction}`;
}

/** Parse a policy cap and require it to be strictly positive. */
export function parsePositiveMoneyAtomic(
  value: unknown,
  asset: MoneyAssetMetadata,
): bigint {
  const atomic = parseMoneyAtomic(value, asset);
  if (atomic === 0n) {
    throw new MoneyParseError("amount-must-be-positive", "Money amount must be positive");
  }
  return atomic;
}
