import { describe, expect, it } from "vitest";
import { decodeDeterministic, encodeDeterministic } from "../src/cbor.js";
import type { CborValue } from "../src/cbor.js";

function bytes(...values: number[]): Uint8Array {
  return Uint8Array.of(...values);
}

describe("deterministic CBOR profile", () => {
  it("uses preferred integer encodings", () => {
    expect(encodeDeterministic(23n)).toEqual(bytes(0x17));
    expect(encodeDeterministic(24n)).toEqual(bytes(0x18, 0x18));
    expect(encodeDeterministic(-1n)).toEqual(bytes(0x20));
    expect(encodeDeterministic(-25n)).toEqual(bytes(0x38, 0x18));
  });

  it("orders map keys by deterministic encoded-key ordering", () => {
    const value = new Map<CborValue, CborValue>([
      [-1n, 1n],
      [1n, 2n],
      [24n, 3n],
    ]);
    expect(encodeDeterministic(value)).toEqual(bytes(0xa3, 0x01, 0x02, 0x20, 0x01, 0x18, 0x18, 0x03));
  });

  it("round-trips permitted primitives", () => {
    const entries: ReadonlyArray<readonly [CborValue, CborValue]> = [
      [1n, bytes(1, 2, 3)],
      [2n, "OpenIdentity"],
      [3n, [1n, null, -7n]],
    ];
    const value = new Map<CborValue, CborValue>(entries);
    expect(encodeDeterministic(decodeDeterministic(encodeDeterministic(value)))).toEqual(
      encodeDeterministic(value),
    );
  });

  it("rejects non-preferred integer encoding", () => {
    expect(() => decodeDeterministic(bytes(0x18, 0x01))).toThrow(/Non-preferred/u);
  });

  it("rejects indefinite lengths", () => {
    expect(() => decodeDeterministic(bytes(0x9f, 0xff))).toThrow(/Indefinite/u);
  });

  it("rejects floats, tags, and trailing bytes", () => {
    expect(() => decodeDeterministic(bytes(0xf9, 0x00, 0x00))).toThrow();
    expect(() => decodeDeterministic(bytes(0xc0, 0x00))).toThrow(/tags/u);
    expect(() => decodeDeterministic(bytes(0x01, 0x01))).toThrow(/Trailing/u);
  });

  it("rejects duplicate and non-canonically ordered map keys", () => {
    expect(() => decodeDeterministic(bytes(0xa2, 0x01, 0x00, 0x01, 0x01))).toThrow(/Duplicate/u);
    expect(() => decodeDeterministic(bytes(0xa2, 0x18, 0x18, 0x00, 0x01, 0x00))).toThrow(
      /ordering/u,
    );
  });
});
