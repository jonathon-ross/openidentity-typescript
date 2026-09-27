import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { StateHash } from "../src/index.js";

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

describe("Protocol v0.1.1 StateHash vectors", () => {
  for (const vector of bundle.vectors) {
    it(vector.id, () => {
      const stateBytes = Uint8Array.from(Buffer.from(vector.stateBytesHex, "hex"));
      expect(StateHash.fromStateBytes(stateBytes).toHex()).toBe(vector.stateHashHex);
    });
  }
});
