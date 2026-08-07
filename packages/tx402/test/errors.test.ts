/**
 * Error-model behavior the conformance vectors cannot cover.
 *
 * `errors.taxonomy.frozen` pins the *table* — codes, class names, retryability. These tests
 * cover what instances actually do: prototype chains, redaction, and the type guard.
 */

import { describe, expect, it } from "vitest";

import {
  AmbiguousPaymentError,
  BudgetExceededError,
  ClockSkewError,
  ConfigurationError,
  DomainNotAllowedError,
  InsufficientLiquidityError,
  InvalidPaymentRequiredError,
  NonReplayableRequestError,
  PaidRedirectBlockedError,
  ReservedHeaderError,
  ResourceDeliveryError,
  SignerError,
  TX402_ERROR_TAXONOMY,
  TransportError,
  Tx402Error,
  UnsupportedProtocolError,
  UnsupportedSchemeError,
  isTx402Error,
  type Tx402ErrorContext,
} from "../src/core/errors.js";

const context: Tx402ErrorContext = { requestId: "req-1", phase: "policy" };

describe("Tx402Error", () => {
  it("keeps instanceof working for both the subclass and the base class", () => {
    // Subclassing Error can lose the prototype chain when the class is transpiled or
    // crosses a bundling boundary, which would silently break every consumer's catch block.
    const error = new BudgetExceededError("over cap", { context });
    expect(error).toBeInstanceOf(BudgetExceededError);
    expect(error).toBeInstanceOf(Tx402Error);
    expect(error).toBeInstanceOf(Error);
  });

  it("takes its name from the taxonomy, not from the class identifier", () => {
    expect(new BudgetExceededError("over cap", { context }).name).toBe(
      "BudgetExceededError",
    );
  });

  it("derives retryable from retryability — only transport is automatically retryable", () => {
    expect(new TransportError("reset", { context }).retryable).toBe(true);
    expect(new TransportError("reset", { context }).retryability).toBe("caller-policy");

    // Conditional, after-correction, and no-automatic-retry all mean "not without the
    // caller doing something first", so all three report false (ADR-011).
    expect(new AmbiguousPaymentError("timed out", { context }).retryable).toBe(false);
    expect(new AmbiguousPaymentError("timed out", { context }).retryability).toBe(
      "no-automatic-retry",
    );
  });

  it("freezes context and details so a caught error cannot be mutated in place", () => {
    const error = new ConfigurationError("bad", {
      context,
      details: { configPath: "policy.maxPerHour", reason: "below-per-request-cap" },
    });
    expect(() => {
      (error.details as Record<string, unknown>).reason = "tampered";
    }).toThrow();
    expect(error.details.reason).toBe("below-per-request-cap");
  });

  it("omits cause and stack from toJSON (SEC-003)", () => {
    // The underlying error routinely comes from a signer or an HTTP client and may carry a
    // payload, a URL with credentials, or a stack referencing either. Serializing it would
    // leak all of that into whatever consumes the diagnostic stream.
    const cause = new Error("signer said: private key 0xdeadbeefcafe");
    const error = new AmbiguousPaymentError("outcome unknown", {
      context: { ...context, phase: "retry", paid: "unknown", reservationId: "r-1" },
      details: { reservationExpiresAtEpochMs: 1, causeCategory: "timeout" },
      cause,
    });

    const serialized = JSON.stringify(error.toJSON());
    expect(serialized).not.toContain("deadbeef");
    expect(serialized).not.toContain("private key");
    expect(Object.keys(error.toJSON())).not.toContain("cause");
    expect(Object.keys(error.toJSON())).not.toContain("stack");

    // Still reachable for debugging, just never serialized.
    expect(error.cause).toBe(cause);
  });

  it('carries paid: "unknown" as a distinct third state, not a missing boolean', () => {
    const error = new AmbiguousPaymentError("outcome unknown", {
      context: { ...context, phase: "retry", paid: "unknown" },
    });
    expect(error.context.paid).toBe("unknown");
    expect(error.toJSON().context.paid).toBe("unknown");
  });

  it("rejects a code outside the taxonomy", () => {
    expect(() => new Tx402Error("TX402_MADE_UP" as never, "nope", { context })).toThrow(
      /Unknown tx402 error code/,
    );
  });
});

describe("isTx402Error", () => {
  it("accepts every class in the taxonomy", () => {
    expect(isTx402Error(new ConfigurationError("bad", { context }))).toBe(true);
    expect(isTx402Error(new TransportError("reset", { context }))).toBe(true);
  });

  it("accepts a structurally valid error from another realm", () => {
    // A worker thread, or a second bundled copy of the package, produces an error that is
    // not `instanceof` this module's class but is otherwise identical. Both are plausible
    // in the agent runtimes this SDK targets, so the guard checks shape too.
    const fromElsewhere = { code: "TX402_TRANSPORT", context, message: "reset" };
    expect(isTx402Error(fromElsewhere)).toBe(true);
  });

  it("rejects plain errors, null, and lookalikes with an unknown code", () => {
    expect(isTx402Error(new Error("boom"))).toBe(false);
    expect(isTx402Error(null)).toBe(false);
    expect(isTx402Error(undefined)).toBe(false);
    expect(isTx402Error("TX402_TRANSPORT")).toBe(false);
    expect(isTx402Error({ code: "TX402_NOT_REAL", context })).toBe(false);
    expect(isTx402Error({ code: "TX402_TRANSPORT" })).toBe(false);
  });
});

describe("taxonomy table", () => {
  it("has a unique code and a unique class name per entry", () => {
    const codes = TX402_ERROR_TAXONOMY.map((entry) => entry.code);
    const classNames = TX402_ERROR_TAXONOMY.map((entry) => entry.className);
    expect(new Set(codes).size).toBe(codes.length);
    expect(new Set(classNames).size).toBe(classNames.length);
  });

  it("gives every entry at least one required detail key", () => {
    // SPEC §8's "required context" column is non-empty for every row. An error that reports
    // nothing specific is not actionable.
    for (const entry of TX402_ERROR_TAXONOMY) {
      expect(entry.requiredDetails.length).toBeGreaterThan(0);
    }
  });

  it("has a constructible, correctly coded class for every row", () => {
    // Instantiating all fifteen is the only way to catch a subclass wired to the wrong
    // code — a copy-paste slip that nothing else in the suite would notice.
    const classes: Record<string, new (message: string, options: never) => Tx402Error> = {
      ConfigurationError,
      ReservedHeaderError,
      NonReplayableRequestError,
      UnsupportedProtocolError,
      UnsupportedSchemeError,
      InvalidPaymentRequiredError,
      BudgetExceededError,
      DomainNotAllowedError,
      InsufficientLiquidityError,
      SignerError,
      ClockSkewError,
      AmbiguousPaymentError,
      ResourceDeliveryError,
      PaidRedirectBlockedError,
      TransportError,
    };

    expect(Object.keys(classes)).toEqual(TX402_ERROR_TAXONOMY.map((e) => e.className));

    for (const entry of TX402_ERROR_TAXONOMY) {
      const Constructor = classes[entry.className];
      if (!Constructor) throw new Error(`No exported class for ${entry.className}`);

      const error = new Constructor("test", { context } as never);
      expect(error.code).toBe(entry.code);
      expect(error.name).toBe(entry.className);
      expect(error.retryable).toBe(entry.retryable);
      expect(error.retryability).toBe(entry.retryability);
      expect(error.descriptor).toBe(entry);
      expect(isTx402Error(error)).toBe(true);
    }
  });

  it("is frozen, table and rows alike", () => {
    expect(Object.isFrozen(TX402_ERROR_TAXONOMY)).toBe(true);
    for (const entry of TX402_ERROR_TAXONOMY) {
      expect(Object.isFrozen(entry)).toBe(true);
      expect(Object.isFrozen(entry.requiredDetails)).toBe(true);
    }
  });
});
