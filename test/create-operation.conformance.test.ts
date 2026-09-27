import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { decodeDeterministic } from "../src/cbor.js";
import type { CborValue } from "../src/cbor.js";
import {
  decodeCreateOperation,
  encodeCreateOperation,
  encodeOperationSigningInput,
} from "../src/operation.js";

interface CreateVector {
  id: string;
  description: string;
  operationBytesHex: string;
  signingInputHex: string;
}

interface Bundle {
  valid: CreateVector[];
}

const bundle = JSON.parse(
  readFileSync(
    new URL("../protocol/v0.1.1/cryptographic-agility-v0.1.json", import.meta.url),
    "utf8",
  ),
) as Bundle;

describe("Protocol v0.1.1 CREATE operations", () => {
  for (const vector of bundle.valid.filter((candidate) =>
    candidate.description.includes("CREATE"),
  )) {
    it(vector.id + " decodes and re-encodes OperationBytes byte-for-byte", () => {
      const expected = Uint8Array.from(Buffer.from(vector.operationBytesHex, "hex"));
      const operation = decodeCreateOperation(expected);
      expect(encodeCreateOperation(operation)).toEqual(expected);
      expect(Buffer.from(encodeOperationSigningInput(expected)).toString("hex")).toBe(
        vector.signingInputHex,
      );
    });
  }
});
