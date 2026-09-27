import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { decodeIdentityState } from "../src/state-codec.js";
import { decodeOperation } from "../src/operation.js";
import { applyRecover } from "../src/transitions.js";

interface Vector {
  id: string;
  expectedError: string;
  previousIdentityStateHex: string;
  operationBytesHex: string;
}

interface Bundle {
  invalidVectors: Vector[];
}

const bundle = JSON.parse(
  readFileSync(new URL("../protocol/v0.1.1/recovery-v0.1.json", import.meta.url), "utf8"),
) as Bundle;

describe("remaining frozen recovery invalid vectors", () => {
  for (const vector of bundle.invalidVectors.filter((candidate) =>
    ["RI01", "RI02", "RI03"].includes(candidate.id),
  )) {
    it(vector.id + " rejects", () => {
      const current = decodeIdentityState(
        Uint8Array.from(Buffer.from(vector.previousIdentityStateHex, "hex")),
      );
      expect(() => {
        const operation = decodeOperation(
          Uint8Array.from(Buffer.from(vector.operationBytesHex, "hex")),
        );
        if (operation.operationType !== 3) throw new Error("Expected RECOVER");
        applyRecover(current, operation);
      }).toThrow();
    });
  }
});
