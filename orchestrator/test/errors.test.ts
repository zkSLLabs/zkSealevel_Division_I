import { describe, it, expect } from "vitest";
import { mapProgramError } from "../src/errors.js";

describe("mapProgramError", () => {
  it("maps known program errors to 400-class codes", () => {
    const cases: Array<[string, string, number]> = [
      ["BadEd25519Order", "BadEd25519Order", 400],
      ["6016", "BadDomainSeparation", 400],
      ["NonMonotonicSeq", "NonMonotonicSeq", 400],
      ["RangeOverlap", "RangeOverlap", 400],
      ["ClockSkew", "ClockSkew", 400],
      ["AggregatorMismatch", "AggregatorMismatch", 400],
      ["InvalidMint", "InvalidMint", 400],
      ["Paused", "Paused", 403],
    ];
    for (const [msg, code, http] of cases) {
      const m = mapProgramError(new Error(msg));
      expect(m.code).toBe(code);
      expect(m.http).toBe(http);
    }
  });

  it("falls back to 500 AnchorSubmitFailed for unknown messages", () => {
    const m = mapProgramError(new Error("some unexpected failure"));
    expect(m.code).toBe("AnchorSubmitFailed");
    expect(m.http).toBe(500);
  });
});


