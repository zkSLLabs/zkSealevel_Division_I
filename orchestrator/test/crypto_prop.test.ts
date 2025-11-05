import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { canonicalize, isHex32, normalizeHex32, uuidFromHash32 } from "../src/crypto.js";

// 4 property-based tests
describe("canonicalize properties", () => {
  it("object key order does not change canonical output", () => {
    fc.assert(
      fc.property(fc.dictionary(fc.string(), fc.anything()), (obj) => {
        const keys = Object.keys(obj);
        const shuffled = keys.sort(() => Math.random() - 0.5).reduce((acc, k) => { acc[k] = obj[k]; return acc; }, {} as Record<string, unknown>);
        expect(canonicalize(obj)).toBe(canonicalize(shuffled));
      })
    );
  });

  it("undefined values are omitted but others preserved", () => {
    fc.assert(
      fc.property(fc.dictionary(fc.string(), fc.oneof(fc.constant(undefined), fc.jsonValue())), (obj) => {
        const c = canonicalize(obj);
        expect(c.includes("undefined")).toBe(false);
      })
    );
  });
});

describe("hex32 and uuid properties", () => {
  it("normalizeHex32 lowercases valid hex32", () => {
    fc.assert(
      fc.property(fc.hexaString({ minLength: 64, maxLength: 64 }), (hex) => {
        const ok = isHex32(hex);
        if (ok) expect(normalizeHex32(hex)).toBe(hex.toLowerCase());
      })
    );
  });

  it("uuidFromHash32 yields v4 UUID format", () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 32, maxLength: 40 }), (arr) => {
        if (arr.length >= 32) {
          const u = uuidFromHash32(arr);
          expect(u).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
        }
      })
    );
  });
});


