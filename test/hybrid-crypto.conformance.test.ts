import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { decodeOperation, encodeOperationSigningInput } from "../src/operation.js";
import { MlDsa65Key } from "../src/model.js";
import { verifyMlDsa65 } from "../src/crypto.js";
import { decodeSignedOperation } from "../src/signed-operation.js";
import { verifyAuthorityPolicy } from "../src/policy-verifier.js";

interface ValidVector {
  id: string;
  operationBytesHex: string;
  signedOperationHex: string;
  authorizationSigningInputHex: string;
  controllerMlDsa65PublicKeyHex?: string;
  controllerMlDsa65AuthorizationSignatureHex?: string;
}

interface InvalidVector {
  id: string;
  expectedError: string;
  operationBytesHex?: string;
  signedOperationHex?: string;
}

interface Bundle {
  valid: ValidVector[];
  invalid: InvalidVector[];
}

const bundle = JSON.parse(
  readFileSync(
    new URL("../protocol/v0.1.1/cryptographic-agility-v0.1.json", import.meta.url),
    "utf8",
  ),
) as Bundle;

describe("Protocol v0.1.1 hybrid cryptographic verification", () => {
  for (const vector of bundle.valid.filter(
    (candidate) =>
      candidate.controllerMlDsa65PublicKeyHex !== undefined &&
      candidate.controllerMlDsa65AuthorizationSignatureHex !== undefined,
  )) {
    it(vector.id + " verifies frozen ML-DSA-65 authorization signature", () => {
      const key = new MlDsa65Key(
        Uint8Array.from(Buffer.from(vector.controllerMlDsa65PublicKeyHex ?? "", "hex")),
      );
      expect(
        verifyMlDsa65(
          key,
          Uint8Array.from(Buffer.from(vector.authorizationSigningInputHex, "hex")),
          Uint8Array.from(
            Buffer.from(vector.controllerMlDsa65AuthorizationSignatureHex ?? "", "hex"),
          ),
        ),
      ).toBe(true);
    });

    it(vector.id + " satisfies its hybrid controller threshold", () => {
      const operationBytes = Uint8Array.from(Buffer.from(vector.operationBytesHex, "hex"));
      const operation = decodeOperation(operationBytes);
      if (operation.operationType !== 1) return;
      const signed = decodeSignedOperation(
        Uint8Array.from(Buffer.from(vector.signedOperationHex, "hex")),
      );
      expect(
        verifyAuthorityPolicy(
          operation.controllerPolicy,
          encodeOperationSigningInput(operationBytes),
          signed.authorizationProofs ?? [],
        ),
      ).toBe(true);
    });
  }
});
