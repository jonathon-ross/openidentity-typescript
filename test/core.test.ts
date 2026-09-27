import { describe, expect, it } from "vitest";
import { IdentityId, StateHash, VerificationMethodId } from "../src/index.js";

describe("core value types", () => {
  it("defensively copies IdentityId bytes", () => {
    const source = new Uint8Array(32);
    const id = new IdentityId(source);
    source[0] = 1;
    expect(id.toHex()).toBe("00".repeat(32));
    const returned = id.bytes();
    returned[0] = 2;
    expect(id.toHex()).toBe("00".repeat(32));
  });

  it("enforces VerificationMethodId length", () => {
    expect(() => new VerificationMethodId(new Uint8Array(15))).toThrow(RangeError);
    expect(new VerificationMethodId(new Uint8Array(16)).bytes()).toHaveLength(16);
  });

  it("rejects a raw SHA-256 digest as StateHash", () => {
    expect(() => new StateHash(new Uint8Array(32))).toThrow(RangeError);
  });
});
