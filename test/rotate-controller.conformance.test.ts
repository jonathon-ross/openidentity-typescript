import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  decodeOperation,
  encodeControllerProofSigningInput,
  encodeOperation,
  encodeOperationSigningInput,
} from "../src/operation.js";
import { VerificationMethodId } from "../src/verification-method-id.js";

interface RotateVector {
  id: string;
  operationBytesHex: string;
  authorizationSigningInputHex: string;
  newEd25519MethodIdHex: string;
  newMlDsa65MethodIdHex: string;
  newEd25519PopSigningInputHex: string;
  newMlDsa65PopSigningInputHex: string;
}

interface Bundle {
  valid: Array<RotateVector & { description: string }>;
}

const bundle = JSON.parse(
  readFileSync(
    new URL("../protocol/v0.1.1/cryptographic-agility-v0.1.json", import.meta.url),
    "utf8",
  ),
) as Bundle;

const vector = bundle.valid.find((candidate) => candidate.id === "V04");
if (vector === undefined) throw new Error("Missing V04 ROTATE_CONTROLLER vector");

describe("Protocol v0.1.1 ROTATE_CONTROLLER", () => {
  it("V04 decodes and re-encodes OperationBytes byte-for-byte", () => {
    const expected = Uint8Array.from(Buffer.from(vector.operationBytesHex, "hex"));
    const operation = decodeOperation(expected);
    expect(operation.operationType).toBe(2);
    expect(encodeOperation(operation)).toEqual(expected);
  });

  it("V04 reconstructs ordinary authorization signing input", () => {
    const operationBytes = Uint8Array.from(Buffer.from(vector.operationBytesHex, "hex"));
    expect(Buffer.from(encodeOperationSigningInput(operationBytes)).toString("hex")).toBe(
      vector.authorizationSigningInputHex,
    );
  });

  it("V04 reconstructs both new-controller proof-of-possession signing inputs", () => {
    const operationBytes = Uint8Array.from(Buffer.from(vector.operationBytesHex, "hex"));
    const ed = VerificationMethodId.fromHex(vector.newEd25519MethodIdHex);
    const ml = VerificationMethodId.fromHex(vector.newMlDsa65MethodIdHex);
    expect(Buffer.from(encodeControllerProofSigningInput(operationBytes, ed)).toString("hex")).toBe(
      vector.newEd25519PopSigningInputHex,
    );
    expect(Buffer.from(encodeControllerProofSigningInput(operationBytes, ml)).toString("hex")).toBe(
      vector.newMlDsa65PopSigningInputHex,
    );
  });
});
