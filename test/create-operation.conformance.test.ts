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

function operationType(operationBytesHex: string): bigint {
  const decoded = decodeDeterministic(Uint8Array.from(Buffer.from(operationBytesHex, "hex")));
  if (!(decoded instanceof Map)) throw new RangeError("Expected operation map");
  const operation: ReadonlyMap<CborValue, CborValue> = decoded;
  const type = operation.get(2n);
  if (typeof type !== "bigint") throw new RangeError("Expected operation type");
  return type;
}

describe("Protocol v0.1.1 CREATE operations", () => {
  for (const vector of bundle.valid.filter(
    (candidate) => operationType(candidate.operationBytesHex) === 1n,
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
