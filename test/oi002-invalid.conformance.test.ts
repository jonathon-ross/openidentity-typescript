import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { decodeOperation } from "../src/operation.js";
import { decodeSignedOperation } from "../src/signed-operation.js";
import { verifyCreateSignedOperation } from "../src/verifier.js";

interface Vector {
  id: string;
  expectedError: string;
  operationBytesHex: string;
  signedOperationHex?: string;
}

interface Bundle {
  invalid: Vector[];
}

const bundle = JSON.parse(
  readFileSync(
    new URL("../protocol/v0.1.1/cryptographic-agility-v0.1.json", import.meta.url),
    "utf8",
  ),
) as Bundle;

describe("frozen OI-002 invalid vectors", () => {
  for (const vector of bundle.invalid.filter((candidate) =>
    ["I01", "I02", "I03", "I04", "I05", "I18", "I19", "I20"].includes(candidate.id),
  )) {
    it(vector.id + " rejects structurally", () => {
      expect(() =>
        decodeOperation(Uint8Array.from(Buffer.from(vector.operationBytesHex, "hex"))),
      ).toThrow();
    });
  }

  for (const vector of bundle.invalid.filter((candidate) =>
    ["I06", "I07", "I08", "I09", "I10"].includes(candidate.id),
  )) {
    it(vector.id + " rejects CREATE authorization", () => {
      if (vector.signedOperationHex === undefined) throw new Error("Missing SignedOperation");
      expect(() => {
        verifyCreateSignedOperation(
          decodeSignedOperation(Uint8Array.from(Buffer.from(vector.signedOperationHex, "hex"))),
        );
      }).toThrow();
    });
  }
});
