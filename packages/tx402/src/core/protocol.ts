/** Strict x402 v2 challenge decoding and tx402 normalization (SPEC §6.2). */

import { createHash } from "node:crypto";

import { decodePaymentRequiredHeader } from "@x402/core/http";

import { canonicalizeJson } from "./canonical-json.js";
import {
  InvalidPaymentRequiredError,
  UnsupportedProtocolError,
  type Tx402ErrorContext,
} from "./errors.js";

export const MAX_PAYMENT_REQUIRED_BYTES = 64 * 1024;
export const MAX_PAYMENT_REQUIRED_DEPTH = 16;
export const MAX_PAYMENT_REQUIREMENTS = 32;

export interface NormalizedPaymentRequirement {
  readonly index: number;
  readonly scheme: string;
  readonly network: string;
  readonly asset: string;
  readonly amountAtomic: string;
  readonly payTo: string;
  readonly maxTimeoutSeconds: number;
  readonly extra: Readonly<Record<string, unknown>>;
  readonly rawHash: string;
}

export interface NormalizedPaymentRequired {
  readonly protocolVersion: 2;
  readonly resource: Readonly<{ url: string; method: string }>;
  readonly requirements: readonly NormalizedPaymentRequirement[];
  readonly receivedAt: string;
  readonly headerHash: string;
  readonly error?: string;
}

export interface DecodePaymentRequiredOptions {
  readonly requestUrl: string | URL;
  readonly requestMethod: string;
  readonly requestId: string;
  readonly clockEpochMs?: number;
  readonly allowInsecureLocalhost?: boolean;
}

type UpstreamRequirement = {
  scheme: string;
  network: string;
  asset: string;
  amount: string;
  payTo: string;
  maxTimeoutSeconds: number;
  extra: Record<string, unknown>;
};

type UpstreamPaymentRequired = {
  x402Version: number;
  resource: { url: string };
  accepts: UpstreamRequirement[];
  error?: string;
};

class JsonPreflightError extends Error {
  constructor(
    readonly reason: "duplicate-json-key" | "json-depth-exceeded" | "invalid-json",
  ) {
    super(reason);
  }
}

/**
 * Validates JSON structure before `JSON.parse`, which otherwise silently keeps the last
 * duplicate object member. This deliberately parses only grammar and keys; upstream still
 * owns conversion of the envelope into its protocol object (ADR-010 decision 6).
 */
function preflightJson(text: string): void {
  let offset = 0;

  const whitespace = (): void => {
    while (/\s/u.test(text[offset] ?? "")) offset += 1;
  };

  const string = (): string => {
    const start = offset;
    if (text[offset] !== '"') throw new JsonPreflightError("invalid-json");
    offset += 1;
    while (offset < text.length) {
      const character = text[offset];
      if (character === '"') {
        offset += 1;
        try {
          return JSON.parse(text.slice(start, offset)) as string;
        } catch {
          throw new JsonPreflightError("invalid-json");
        }
      }
      if (character === "\\") {
        offset += 2;
      } else {
        if (character === undefined || character.charCodeAt(0) < 0x20) {
          throw new JsonPreflightError("invalid-json");
        }
        offset += 1;
      }
    }
    throw new JsonPreflightError("invalid-json");
  };

  const value = (depth: number): void => {
    whitespace();
    const character = text[offset];
    if (character === "{" || character === "[") {
      if (depth > MAX_PAYMENT_REQUIRED_DEPTH) {
        throw new JsonPreflightError("json-depth-exceeded");
      }
      if (character === "{") object(depth);
      else array(depth);
      return;
    }
    if (character === '"') {
      string();
      return;
    }
    const rest = text.slice(offset);
    const token = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/u.exec(
      rest,
    )?.[0];
    if (!token) throw new JsonPreflightError("invalid-json");
    offset += token.length;
  };

  const object = (depth: number): void => {
    offset += 1;
    whitespace();
    const keys = new Set<string>();
    if (text[offset] === "}") {
      offset += 1;
      return;
    }
    while (true) {
      whitespace();
      const key = string();
      if (keys.has(key)) throw new JsonPreflightError("duplicate-json-key");
      keys.add(key);
      whitespace();
      if (text[offset] !== ":") throw new JsonPreflightError("invalid-json");
      offset += 1;
      value(depth + 1);
      whitespace();
      if (text[offset] === "}") {
        offset += 1;
        return;
      }
      if (text[offset] !== ",") throw new JsonPreflightError("invalid-json");
      offset += 1;
    }
  };

  const array = (depth: number): void => {
    offset += 1;
    whitespace();
    if (text[offset] === "]") {
      offset += 1;
      return;
    }
    while (true) {
      value(depth + 1);
      whitespace();
      if (text[offset] === "]") {
        offset += 1;
        return;
      }
      if (text[offset] !== ",") throw new JsonPreflightError("invalid-json");
      offset += 1;
    }
  };

  value(1);
  whitespace();
  if (offset !== text.length) throw new JsonPreflightError("invalid-json");
}

function digest(value: string): string {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function invalid(
  reason: string,
  context: Tx402ErrorContext,
  schemaPath = "/",
  cause?: unknown,
): InvalidPaymentRequiredError {
  return new InvalidPaymentRequiredError(`Invalid PAYMENT-REQUIRED challenge: ${reason}`, {
    context,
    details: { reason, schemaPath },
    ...(cause === undefined ? {} : { cause }),
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isLocalhost(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/gu, "");
  return normalized === "localhost" || normalized === "127.0.0.1" || normalized === "::1";
}

function validateRequirement(
  value: unknown,
  index: number,
  context: Tx402ErrorContext,
): UpstreamRequirement {
  if (!isRecord(value))
    throw invalid("upstream-schema-invalid", context, `/accepts/${index}`);
  const { scheme, network, asset, amount, payTo, maxTimeoutSeconds, extra } = value;
  if (
    typeof scheme !== "string" ||
    scheme.length === 0 ||
    scheme.length > 64 ||
    typeof network !== "string" ||
    !/^[a-z0-9-]{3,8}:[A-Za-z0-9-]{1,48}$/u.test(network) ||
    typeof asset !== "string" ||
    asset.length === 0 ||
    asset.length > 128 ||
    typeof payTo !== "string" ||
    payTo.length === 0 ||
    payTo.length > 128 ||
    !Number.isInteger(maxTimeoutSeconds) ||
    (maxTimeoutSeconds as number) < 1 ||
    (maxTimeoutSeconds as number) > 86_400 ||
    !isRecord(extra)
  ) {
    throw invalid("upstream-schema-invalid", context, `/accepts/${index}`);
  }
  if (typeof amount !== "string" || !/^[1-9][0-9]*$/u.test(amount)) {
    throw invalid("amount-not-atomic-integer", context, `/accepts/${index}/amount`);
  }
  return {
    scheme,
    network,
    asset,
    amount,
    payTo,
    maxTimeoutSeconds: maxTimeoutSeconds as number,
    extra,
  };
}

/** Decode, bound, validate, and normalize one raw PAYMENT-REQUIRED header. */
export function decodePaymentRequired(
  header: string | null | undefined,
  options: DecodePaymentRequiredOptions,
): NormalizedPaymentRequired {
  const context: Tx402ErrorContext = { requestId: options.requestId, phase: "parse" };
  if (header === null || header === undefined || header.length === 0) {
    throw invalid("missing-header", context);
  }
  if (!/^[A-Za-z0-9+/]*={0,2}$/u.test(header) || header.length % 4 !== 0) {
    throw invalid("invalid-base64", context);
  }

  let bytes: Uint8Array;
  let jsonText: string;
  try {
    bytes = Buffer.from(header, "base64");
    if (bytes.byteLength > MAX_PAYMENT_REQUIRED_BYTES)
      throw invalid("header-too-large", context);
    jsonText = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    if (error instanceof InvalidPaymentRequiredError) throw error;
    throw invalid("invalid-base64", context, "/", error);
  }

  try {
    preflightJson(jsonText);
  } catch (error) {
    const reason = error instanceof JsonPreflightError ? error.reason : "invalid-json";
    throw invalid(reason, context, "/", error);
  }

  let decoded: unknown;
  try {
    decoded = decodePaymentRequiredHeader(header);
  } catch (error) {
    throw invalid("invalid-json", context, "/", error);
  }
  if (!isRecord(decoded)) throw invalid("upstream-schema-invalid", context);
  if (decoded.x402Version !== 2) {
    throw new UnsupportedProtocolError("Unsupported x402 protocol version", {
      context,
      details: {
        observedVersion: decoded.x402Version,
        supportedVersions: [2],
        reason: "unsupported-protocol-version",
      },
    });
  }
  if (!isRecord(decoded.resource) || typeof decoded.resource.url !== "string") {
    throw invalid("upstream-schema-invalid", context, "/resource");
  }
  if (
    !Array.isArray(decoded.accepts) ||
    decoded.accepts.length < 1 ||
    decoded.accepts.length > MAX_PAYMENT_REQUIREMENTS
  ) {
    throw invalid("requirements-count-out-of-range", context, "/accepts");
  }

  let declaredUrl: URL;
  let requestUrl: URL;
  try {
    declaredUrl = new URL(decoded.resource.url);
    requestUrl = new URL(options.requestUrl);
  } catch (error) {
    throw invalid("resource-url-invalid", context, "/resource/url", error);
  }
  const secure = declaredUrl.protocol === "https:";
  const permittedLocalHttp =
    options.allowInsecureLocalhost === true &&
    declaredUrl.protocol === "http:" &&
    requestUrl.protocol === "http:" &&
    isLocalhost(declaredUrl.hostname) &&
    isLocalhost(requestUrl.hostname);
  if ((!secure && !permittedLocalHttp) || declaredUrl.origin !== requestUrl.origin) {
    throw invalid("resource-origin-mismatch", context, "/resource/url");
  }

  const upstream = decoded as unknown as UpstreamPaymentRequired;
  const requirements = upstream.accepts.map((entry, index) => {
    const requirement = validateRequirement(entry, index, context);
    return Object.freeze({
      index,
      scheme: requirement.scheme,
      network: requirement.network,
      asset: requirement.asset,
      amountAtomic: requirement.amount,
      payTo: requirement.payTo,
      maxTimeoutSeconds: requirement.maxTimeoutSeconds,
      extra: Object.freeze({ ...requirement.extra }),
      rawHash: (() => {
        try {
          return digest(canonicalizeJson(requirement));
        } catch (error) {
          throw invalid("upstream-schema-invalid", context, `/accepts/${index}`, error);
        }
      })(),
    });
  });

  const normalized = {
    protocolVersion: 2 as const,
    resource: Object.freeze({
      url: decoded.resource.url,
      method: options.requestMethod.toUpperCase(),
    }),
    requirements: Object.freeze(requirements),
    receivedAt: new Date(options.clockEpochMs ?? Date.now()).toISOString(),
    headerHash: digest(header),
    ...(typeof decoded.error === "string" ? { error: decoded.error } : {}),
  };
  return Object.freeze(normalized);
}
