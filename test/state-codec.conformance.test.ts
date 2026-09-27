import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { StateHash } from "../src/state-hash.js";
import { decodeIdentityState, encodeIdentityState } from "../src/state-codec.js";

interface StateHashVector {
  id: string;
  stateBytesHex: string;
  stateHashHex: string;
}

interface StateHashBundle {
  vectors: StateHashVector[];
}

const bundle = JSON.parse(
  readFileSync(new URL("../protocol/v0.1.1/state-hash-v0.1.json", import.meta.url), "utf8"),
) as StateHashBundle;

describe("Protocol v0.1.1 IdentityState deterministic CBOR", () => {
  for (const vector of bundle.vectors) {
    it(vector.id + " decodes and re-encodes StateBytes byte-for-byte", () => {
      const expected = Uint8Array.from(Buffer.from(vector.stateBytesHex, "hex"));
      const state = decodeIdentityState(expected);
      const actual = encodeIdentityState(state);
      expect(actual).toEqual(expected);
      expect(StateHash.fromStateBytes(actual).toHex()).toBe(vector.stateHashHex);
    });
  }
});
