/**
 * Executes the shared conformance suite against the TypeScript SDK (ADR-005).
 *
 * The contract these tests implement is written down once, in
 * `core-spec/conformance/README.md`, and the Python suite at
 * `packages/tx402-python/tests/test_conformance.py` implements the same one.
 */

import { describe, expect, it } from "vitest";

import "./conformance/handlers.js";
import {
  IMPLEMENTED_THROUGH,
  handlerFor,
  loadVectors,
  milestoneIsImplemented,
  missingHandlers,
  stageA,
} from "./conformance/runner.js";

const vectors = loadVectors();

describe("conformance suite", () => {
  it("loads a non-empty, integrity-checked fixture index", () => {
    expect(vectors.length).toBeGreaterThan(0);
  });

  it("has a Stage B handler for every kind at or below the implemented milestone", () => {
    // The check that stops a milestone from being claimed without being implemented. If
    // this fails, either register the handler or lower IMPLEMENTED_THROUGH.
    expect(missingHandlers(vectors)).toEqual([]);
  });
});

/* Stage A — every vector, every milestone. ---------------------------------------------- */

describe("Stage A — fixture integrity and frozen names", () => {
  for (const loaded of vectors) {
    it(`${loaded.entry.id} (${loaded.entry.milestone}) — ${loaded.vector.title}`, () => {
      expect(stageA(loaded).problems).toEqual([]);
    });
  }
});

/* Stage B — implemented milestones only. ------------------------------------------------ */

const executable = vectors.filter(
  ({ vector }) => milestoneIsImplemented(vector.milestone) && handlerFor(vector.kind),
);
const pending = vectors.filter(({ vector }) => !milestoneIsImplemented(vector.milestone));

describe(`Stage B — implementation, through ${IMPLEMENTED_THROUGH}`, () => {
  for (const { vector } of executable) {
    it(`${vector.id} — ${vector.title}`, async () => {
      // Non-null: `executable` filtered on the handler's presence.
      await handlerFor(vector.kind)!(vector);
    });
  }

  it(`reports ${pending.length} vectors pending a later milestone`, () => {
    // Not a skip. Pending vectors have already passed Stage A, and this assertion keeps
    // their count visible in test output so that a milestone's remaining work is never
    // invisible. The set is expected to shrink to zero by M8.
    const byMilestone = new Map<string, number>();
    for (const { vector } of pending) {
      byMilestone.set(vector.milestone, (byMilestone.get(vector.milestone) ?? 0) + 1);
    }
    for (const [milestone] of byMilestone) {
      expect(milestoneIsImplemented(milestone as never)).toBe(false);
    }
    expect(pending.length + executable.length).toBe(vectors.length);
  });
});
