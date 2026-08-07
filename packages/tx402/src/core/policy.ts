/** Local policy evaluation in the exact SPEC §6.3 order. */

import {
  BudgetExceededError,
  ClockSkewError,
  ConfigurationError,
  DomainNotAllowedError,
  InvalidPaymentRequiredError,
  UnsupportedSchemeError,
  type Tx402ErrorContext,
} from "./errors.js";
import type { SpendStore } from "./ledger.js";
import {
  requireNetwork,
  type ManifestAsset,
  type ManifestNetwork,
  type ReleaseManifest,
} from "./manifest.js";
import { MoneyParseError, parsePositiveMoneyAtomic } from "./money.js";
import type {
  NormalizedPaymentRequired,
  NormalizedPaymentRequirement,
} from "./protocol.js";

export interface PolicyConfig {
  readonly maxPerRequest?: unknown;
  readonly maxPerHour?: unknown;
  readonly allowedNetworks?: readonly string[];
  readonly allowedDomains?: readonly string[];
  readonly maxPaidAttempts?: number;
}

export interface RoutingPolicyConfig {
  readonly maxQuoteAgeMs?: number;
  /**
   * Tie-break preference only (SPEC §4.3). Listing a network here cannot make it payable —
   * it must still be offered by the merchant, allowed by policy, present in the manifest, and
   * backed by a sufficient balance. Aliases are accepted and normalized to canonical CAIP-2,
   * because a preference expressed as `solana:mainnet` must match a candidate identified by
   * its genesis hash (ADR-010 decision 4).
   */
  readonly preferNetworks?: readonly string[];
  /**
   * Replaces the signed manifest's RPC endpoints for specific networks (ADR-015).
   *
   * Keyed by CAIP-2 identifier or alias; the value replaces `rpcUrls` for that network and
   * nothing else. Every other manifest fact — which networks exist, which assets they carry,
   * a token's decimals — still comes from the signed document and cannot be overridden here.
   *
   * **This does not weaken the manifest's integrity guarantee.** SPEC §7.1 and §7.2 require
   * chain identity to be proven on the same endpoint that serves the balance, on every read,
   * and that check runs against whatever endpoint is used — so an override that points at
   * the wrong chain opens its circuit and is skipped rather than being trusted. What an
   * override can do is make tx402 unable to read a balance; it cannot make tx402 pay on a
   * network the caller did not allow.
   *
   * Exists because the manifest ships keyless public endpoints, and a keyless public
   * endpoint has a per-IP quota. An operator running at volume has a keyed endpoint and
   * previously had no way to tell tx402 about it (PLAN.md open item O35).
   */
  readonly rpcOverrides?: Readonly<Record<string, readonly string[]>>;
}

export interface PolicyRequirement extends NormalizedPaymentRequirement {
  readonly assetId: string;
  /**
   * The **manifest** asset this requirement was matched to — decimals, symbol, and the
   * canonical address — not the merchant's claim about it. Route planning and the signer
   * presentation read token metadata from here, so a merchant cannot restate a token's
   * decimals and change what an amount means (SPEC §0, ADR-006).
   */
  readonly manifestAsset: ManifestAsset;
  readonly maxPerRequestAtomic: string;
  readonly maxPerHourAtomic: string;
}

export interface PolicyDecision {
  readonly normalizedHost: string;
  readonly requirements: readonly PolicyRequirement[];
}

interface PreparedAsset {
  readonly manifest: ManifestAsset;
  readonly assetId: string;
  readonly maxPerRequest: bigint;
  readonly maxPerHour: bigint;
}

const DEFAULT_MAX_PER_REQUEST = "0.50 USDC";
const DEFAULT_MAX_PER_HOUR = "10.00 USDC";
const DEFAULT_MAX_QUOTE_AGE_MS = 5_000;
const MAX_FUTURE_SKEW_MS = 15_000;

function configContext(): Tx402ErrorContext {
  return { requestId: "configuration", phase: "initial" };
}

function configuration(path: string, reason: string, cause?: unknown): ConfigurationError {
  return new ConfigurationError(`Invalid ${path}: ${reason}`, {
    context: configContext(),
    details: { configPath: path, reason },
    ...(cause === undefined ? {} : { cause }),
  });
}

/**
 * The canonical policy host of `url` (ADR-018, amended S15d).
 *
 * The canonical form is the **A-label (ASCII) host**: what a WHATWG URL parser produces,
 * lowercased, with one trailing root dot removed. `https://bücher.example/x` and
 * `https://xn--bcher-kva.example/x` are therefore one merchant with one ledger and one
 * allowlist entry, in both languages — Python's `normalize_policy_host` returns the same
 * string for the same input, and its parity is pinned by a shared table of hosts.
 *
 * `new URL` does the ToASCII conversion, which is deliberate: it is the same parser
 * `fetch` uses to decide which host the signature is actually sent to, so the ledger key
 * cannot describe a different host from the one that was paid.
 *
 * @throws {TypeError} if `url` is not a parseable absolute URL.
 */
export function normalizePolicyHost(url: string | URL): string {
  // One dot, not every dot: `a.test.` is `a.test`, and `a.test..` keeps the inner one. The
  // root-label host `.` normalizes to the empty string — an accepted, non-routable edge
  // that matches only the `"*"` pattern, which already permits every host (O43).
  return new URL(url).hostname.toLowerCase().replace(/\.$/u, "");
}

function normalizeDomainPattern(value: string, index: number): string {
  if (value === "*") return value;
  const wildcard = value.startsWith("*.");
  const candidate = wildcard ? value.slice(2) : value;
  if (
    candidate.length === 0 ||
    candidate.includes(":") ||
    candidate.includes("/") ||
    candidate.includes("@")
  ) {
    throw configuration(`policy.allowedDomains[${index}]`, "invalid-domain-pattern");
  }
  let host: string;
  try {
    // Through the same normalization the request host gets, so a Unicode allowlist entry
    // and a Unicode request URL land on one string (ADR-018 amendment, O58).
    host = normalizePolicyHost(`https://${candidate}`);
  } catch (error) {
    throw configuration(`policy.allowedDomains[${index}]`, "invalid-domain-pattern", error);
  }
  return wildcard ? `*.${host}` : host;
}

function domainMatches(host: string, pattern: string): boolean {
  if (pattern === "*") return true;
  if (!pattern.startsWith("*.")) return host === pattern;
  const suffix = pattern.slice(1);
  return host.endsWith(suffix) && host.length > suffix.length;
}

function isEvmNetwork(network: ManifestNetwork): boolean {
  return "chainId" in network;
}

function assetReference(asset: ManifestAsset): string {
  return "address" in asset ? asset.address : asset.mint;
}

function assetMatches(
  network: ManifestNetwork,
  asset: ManifestAsset,
  offered: string,
): boolean {
  const expected = assetReference(asset);
  return isEvmNetwork(network)
    ? expected.toLowerCase() === offered.toLowerCase()
    : expected === offered;
}

function assetId(
  networkId: string,
  network: ManifestNetwork,
  asset: ManifestAsset,
): string {
  return `${networkId}/${isEvmNetwork(network) ? "erc20" : "token"}:${assetReference(asset)}`;
}

function timestampFromExtra(extra: Readonly<Record<string, unknown>>): number | undefined {
  if (!("timestamp" in extra)) return undefined;
  const value = extra.timestamp;
  if (typeof value === "string" && value.endsWith("Z")) {
    const parsed = Date.parse(value);
    if (!Number.isNaN(parsed)) return parsed;
  }
  throw new TypeError("quote-timestamp-invalid");
}

/** Immutable policy object. It performs no network or signer calls. */
export class PolicyEngine {
  readonly #manifest: ReleaseManifest;
  readonly #allowedNetworks: ReadonlySet<string>;
  readonly #allowedDomains: readonly string[];
  readonly #assets = new Map<string, PreparedAsset>();
  readonly #maxQuoteAgeMs: number;
  readonly maxPaidAttempts: number;
  /** Canonical CAIP-2, in the caller's stated order (SPEC §6.4 step 18). */
  readonly preferNetworks: readonly string[];
  /** Caller-supplied RPC endpoints, keyed by canonical CAIP-2 (ADR-015). */
  readonly rpcOverrides: Readonly<Record<string, readonly string[]>>;

  constructor(
    manifest: ReleaseManifest,
    policy: PolicyConfig = {},
    routing: RoutingPolicyConfig = {},
  ) {
    this.#manifest = manifest;
    const configuredNetworks =
      policy.allowedNetworks ??
      Object.entries(manifest.networks)
        .filter(([, network]) => network.environment === "production")
        .map(([networkId]) => networkId);
    if (!Array.isArray(configuredNetworks) || configuredNetworks.length === 0) {
      throw configuration("policy.allowedNetworks", "empty-list");
    }
    const resolvedNetworks = configuredNetworks.map((network, index) => {
      if (typeof network !== "string") {
        throw configuration(`policy.allowedNetworks[${index}]`, "expected-string");
      }
      return requireNetwork(
        manifest,
        network,
        configContext(),
        `policy.allowedNetworks[${index}]`,
      );
    });
    this.#allowedNetworks = new Set(resolvedNetworks);

    const configuredDomains = policy.allowedDomains ?? ["*"];
    if (!Array.isArray(configuredDomains) || configuredDomains.length === 0) {
      throw configuration("policy.allowedDomains", "empty-list");
    }
    this.#allowedDomains = Object.freeze(
      configuredDomains.map((pattern, index) => {
        if (typeof pattern !== "string") {
          throw configuration(`policy.allowedDomains[${index}]`, "expected-string");
        }
        return normalizeDomainPattern(pattern, index);
      }),
    );

    this.maxPaidAttempts = policy.maxPaidAttempts ?? 2;
    if (
      !Number.isInteger(this.maxPaidAttempts) ||
      this.maxPaidAttempts < 1 ||
      this.maxPaidAttempts > 3
    ) {
      throw configuration("policy.maxPaidAttempts", "integer-out-of-range");
    }
    this.#maxQuoteAgeMs = routing.maxQuoteAgeMs ?? DEFAULT_MAX_QUOTE_AGE_MS;
    if (!Number.isInteger(this.#maxQuoteAgeMs) || this.#maxQuoteAgeMs < 0) {
      throw configuration("routing.maxQuoteAgeMs", "expected-non-negative-integer");
    }

    const configuredPreference = routing.preferNetworks ?? [];
    if (!Array.isArray(configuredPreference)) {
      throw configuration("routing.preferNetworks", "expected-array");
    }
    // Resolved through the manifest, so an unknown or misspelled network is a construction
    // error rather than a preference that silently never matches anything.
    this.preferNetworks = Object.freeze(
      configuredPreference.map((network, index) => {
        if (typeof network !== "string") {
          throw configuration(`routing.preferNetworks[${index}]`, "expected-string");
        }
        return requireNetwork(
          manifest,
          network,
          configContext(),
          `routing.preferNetworks[${index}]`,
        );
      }),
    );

    // Resolved through the manifest for the same reason preferences are: an override keyed
    // by a misspelled or aliased network must fail at construction rather than silently
    // never applying, which would leave the operator believing their keyed endpoint is in
    // use while every read still goes to the public one (ADR-015).
    const configuredOverrides = routing.rpcOverrides ?? {};
    if (
      typeof configuredOverrides !== "object" ||
      configuredOverrides === null ||
      Array.isArray(configuredOverrides)
    ) {
      throw configuration("routing.rpcOverrides", "expected-object");
    }
    const overrides = new Map<string, readonly string[]>();
    for (const [network, urls] of Object.entries(configuredOverrides)) {
      const path = `routing.rpcOverrides[${network}]`;
      const resolved = requireNetwork(manifest, network, configContext(), path);
      if (!Array.isArray(urls) || urls.length === 0) {
        throw configuration(path, "empty-list");
      }
      overrides.set(
        resolved,
        Object.freeze(
          urls.map((url, index) => {
            if (typeof url !== "string") {
              throw configuration(`${path}[${index}]`, "expected-string");
            }
            let parsed: URL;
            try {
              parsed = new URL(url);
            } catch {
              throw configuration(`${path}[${index}]`, "invalid-url");
            }
            // An RPC endpoint carries an API key in its path or query often enough that
            // plaintext http would leak it to the network. Localhost is exempt because a
            // local validator has no transport to intercept.
            const local =
              parsed.hostname === "localhost" ||
              parsed.hostname === "127.0.0.1" ||
              parsed.hostname === "[::1]";
            if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && local)) {
              throw configuration(`${path}[${index}]`, "insecure-scheme");
            }
            return url;
          }),
        ),
      );
    }
    this.rpcOverrides = Object.freeze(Object.fromEntries(overrides));

    for (const networkId of this.#allowedNetworks) {
      const network = manifest.networks[networkId];
      if (network === undefined) continue;
      for (const asset of network.assets) {
        let maxPerRequest: bigint;
        let maxPerHour: bigint;
        try {
          maxPerRequest = parsePositiveMoneyAtomic(
            policy.maxPerRequest ?? DEFAULT_MAX_PER_REQUEST,
            asset,
          );
        } catch (error) {
          const reason = error instanceof MoneyParseError ? error.reason : "invalid-money";
          throw configuration("policy.maxPerRequest", reason, error);
        }
        try {
          maxPerHour = parsePositiveMoneyAtomic(
            policy.maxPerHour ?? DEFAULT_MAX_PER_HOUR,
            asset,
          );
        } catch (error) {
          const reason = error instanceof MoneyParseError ? error.reason : "invalid-money";
          throw configuration("policy.maxPerHour", reason, error);
        }
        if (maxPerHour < maxPerRequest) {
          throw configuration("policy.maxPerHour", "below-max-per-request");
        }
        this.#assets.set(`${networkId}\u0000${assetReference(asset)}`, {
          manifest: asset,
          assetId: assetId(networkId, network, asset),
          maxPerRequest,
          maxPerHour,
        });
      }
    }
    Object.freeze(this);
  }

  assertDomain(url: string | URL, requestId: string, phase: "initial" | "policy"): string {
    const host = normalizePolicyHost(url);
    if (!this.#allowedDomains.some((pattern) => domainMatches(host, pattern))) {
      throw new DomainNotAllowedError("Destination domain is not allowed", {
        context: { requestId, phase },
        details: { normalizedHost: host },
      });
    }
    return host;
  }

  async evaluate(
    paymentRequired: NormalizedPaymentRequired,
    options: {
      readonly requestId: string;
      readonly policyScope: string;
      readonly nowEpochMs: number;
      readonly spendStore: SpendStore;
    },
  ): Promise<PolicyDecision> {
    const context: Tx402ErrorContext = { requestId: options.requestId, phase: "policy" };

    // 7. Destination domain.
    const normalizedHost = this.assertDomain(
      paymentRequired.resource.url,
      options.requestId,
      "policy",
    );

    // 8. Supported and allowed networks.
    const networkAllowed = paymentRequired.requirements.filter(
      (requirement) =>
        this.#allowedNetworks.has(requirement.network) &&
        this.#manifest.networks[requirement.network] !== undefined,
    );
    if (networkAllowed.length === 0) {
      throw new UnsupportedSchemeError("No allowed payment network was offered", {
        context,
        details: {
          offeredSchemes: [
            ...new Set(paymentRequired.requirements.map((item) => item.scheme)),
          ],
          offeredNetworks: [
            ...new Set(paymentRequired.requirements.map((item) => item.network)),
          ],
        },
      });
    }

    // 9. Supported schemes and manifest assets.
    const supported: { requirement: NormalizedPaymentRequirement; asset: PreparedAsset }[] =
      [];
    for (const requirement of networkAllowed) {
      const network = this.#manifest.networks[requirement.network];
      if (network === undefined || requirement.scheme !== "exact") continue;
      const matched = network.assets.find(
        (asset) =>
          asset.schemes.includes(requirement.scheme) &&
          assetMatches(network, asset, requirement.asset),
      );
      if (matched === undefined) continue;
      const prepared = this.#assets.get(
        `${requirement.network}\u0000${assetReference(matched)}`,
      );
      if (prepared !== undefined) supported.push({ requirement, asset: prepared });
    }
    if (supported.length === 0) {
      throw new UnsupportedSchemeError(
        "No supported payment scheme and asset was offered",
        {
          context,
          details: {
            offeredSchemes: [...new Set(networkAllowed.map((item) => item.scheme))],
            offeredNetworks: [...new Set(networkAllowed.map((item) => item.network))],
          },
        },
      );
    }

    // 10. Per-request amount.
    const underRequestCap = supported.filter(
      ({ requirement, asset }) => BigInt(requirement.amountAtomic) <= asset.maxPerRequest,
    );
    if (underRequestCap.length === 0) {
      const { requirement, asset } = supported.reduce((best, candidate) =>
        BigInt(candidate.requirement.amountAtomic) < BigInt(best.requirement.amountAtomic)
          ? candidate
          : best,
      );
      throw new BudgetExceededError("Payment exceeds the per-request limit", {
        context: {
          ...context,
          network: requirement.network,
          scheme: requirement.scheme,
          amountAtomic: requirement.amountAtomic,
          assetId: asset.assetId,
        },
        details: {
          requestedAtomic: requirement.amountAtomic,
          capAtomic: asset.maxPerRequest.toString(),
          committedAtomic: "0",
          reservedAtomic: "0",
          capKind: "per-request",
        },
      });
    }

    // 11. Rolling committed plus active reservations. Atomic reserve repeats this check.
    const withinHourlyCap: PolicyRequirement[] = [];
    let lastBudget:
      | {
          requirement: NormalizedPaymentRequirement;
          asset: PreparedAsset;
          committedAtomic: string;
          reservedAtomic: string;
        }
      | undefined;
    for (const { requirement, asset } of underRequestCap) {
      const state = await options.spendStore.getBudgetState({
        policyScope: options.policyScope,
        assetId: asset.assetId,
        nowEpochMs: options.nowEpochMs,
      });
      lastBudget = {
        requirement,
        asset,
        committedAtomic: state.committedAtomic,
        reservedAtomic: state.reservedAtomic,
      };
      if (
        BigInt(state.committedAtomic) +
          BigInt(state.reservedAtomic) +
          BigInt(requirement.amountAtomic) <=
        asset.maxPerHour
      ) {
        withinHourlyCap.push(
          Object.freeze({
            ...requirement,
            assetId: asset.assetId,
            manifestAsset: asset.manifest,
            maxPerRequestAtomic: asset.maxPerRequest.toString(),
            maxPerHourAtomic: asset.maxPerHour.toString(),
          }),
        );
      }
    }
    if (withinHourlyCap.length === 0 && lastBudget !== undefined) {
      throw new BudgetExceededError("Payment would exceed the rolling hourly limit", {
        context: {
          ...context,
          network: lastBudget.requirement.network,
          scheme: lastBudget.requirement.scheme,
          amountAtomic: lastBudget.requirement.amountAtomic,
          assetId: lastBudget.asset.assetId,
        },
        details: {
          requestedAtomic: lastBudget.requirement.amountAtomic,
          capAtomic: lastBudget.asset.maxPerHour.toString(),
          committedAtomic: lastBudget.committedAtomic,
          reservedAtomic: lastBudget.reservedAtomic,
          capKind: "per-hour",
        },
      });
    }

    // 12. Conditional quote timestamp in upstream `extra` (ADR-010 decision 3).
    const fresh = withinHourlyCap.filter((requirement) => {
      let timestamp: number | undefined;
      try {
        timestamp = timestampFromExtra(requirement.extra);
      } catch (error) {
        throw new InvalidPaymentRequiredError("Quote timestamp is invalid", {
          context,
          details: {
            reason: "quote-timestamp-invalid",
            schemaPath: "/accepts/*/extra/timestamp",
          },
          cause: error,
        });
      }
      if (timestamp === undefined) return true;
      const skew = timestamp - options.nowEpochMs;
      if (skew > MAX_FUTURE_SKEW_MS) {
        throw new ClockSkewError("Quote timestamp is unreasonably future-dated", {
          context,
          details: { observedSkewMs: skew, thresholdMs: MAX_FUTURE_SKEW_MS },
        });
      }
      return options.nowEpochMs - timestamp <= this.#maxQuoteAgeMs;
    });
    if (fresh.length === 0) {
      throw new InvalidPaymentRequiredError("Payment quote has expired", {
        context,
        details: { reason: "quote-expired", schemaPath: "/accepts/*/extra/timestamp" },
      });
    }

    return Object.freeze({
      normalizedHost,
      requirements: Object.freeze(fresh),
    });
  }
}
