import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { StateHash } from "../src/state-hash.js";
import { decodeIdentityState, encodeIdentityState } from "../src/state-codec.js";
import {
  decodeOperation,
  encodeControllerProofSigningInput,
  encodeOperation,
  encodeOperationSigningInput,
} from "../src/operation.js";
import { applySetAssertionPolicy } from "../src/transitions.js";
import { VerificationMethodId } from "../src/verification-method-id.js";

interface Vector {
  id: string;
  operationBytesHex: string;
  authorizationSigningInputHex: string;
  previousIdentityStateHex: string;
  resultingIdentityStateHex: string;
  resultingStateHashHex: string;
  assertionEd25519MethodIdHex?: string;
  assertionMlDsa65MethodIdHex?: string;
  assertionEd25519PopSigningInputHex?: string;
  assertionMlDsa65PopSigningInputHex?: string;
}

interface Bundle {
  validVectors: Vector[];
}

const bundle = JSON.parse(
  readFileSync(
    new URL("../protocol/v0.1.1/assertion-authority-v0.1.json", import.meta.url),
    "utf8",
  ),
) as Bundle;

describe("Protocol v0.1.1 SET_ASSERTION_POLICY", () => {
  for (const vector of bundle.validVectors) {
    it(vector.id + " round-trips operation and derives exact resulting state", () => {
      const operationBytes = Uint8Array.from(Buffer.from(vector.operationBytesHex, "hex"));
      const operation = decodeOperation(operationBytes);
      expect(operation.operationType).toBe(5);
      if (operation.operationType !== 5) throw new Error("Expected SET_ASSERTION_POLICY");
      expect(encodeOperation(operation)).toEqual(operationBytes);
      expect(Buffer.from(encodeOperationSigningInput(operationBytes)).toString("hex")).toBe(
        vector.authorizationSigningInputHex,
      );

      const previous = decodeIdentityState(
        Uint8Array.from(Buffer.from(vector.previousIdentityStateHex, "hex")),
      );
      const resulting = applySetAssertionPolicy(previous, operation);
      const stateBytes = encodeIdentityState(resulting);
      expect(Buffer.from(stateBytes).toString("hex")).toBe(vector.resultingIdentityStateHex);
      expect(StateHash.fromStateBytes(stateBytes).toHex()).toBe(vector.resultingStateHashHex);
    });

    it(vector.id + " reconstructs proposed assertion-key PoP inputs when present", () => {
      const operationBytes = Uint8Array.from(Buffer.from(vector.operationBytesHex, "hex"));
      if (
        vector.assertionEd25519MethodIdHex !== undefined &&
        vector.assertionEd25519PopSigningInputHex !== undefined
      ) {
        const id = VerificationMethodId.fromHex(vector.assertionEd25519MethodIdHex);
        expect(
          Buffer.from(encodeControllerProofSigningInput(operationBytes, id)).toString("hex"),
        ).toBe(vector.assertionEd25519PopSigningInputHex);
      }
      if (
        vector.assertionMlDsa65MethodIdHex !== undefined &&
        vector.assertionMlDsa65PopSigningInputHex !== undefined
      ) {
        const id = VerificationMethodId.fromHex(vector.assertionMlDsa65MethodIdHex);
        expect(
          Buffer.from(encodeControllerProofSigningInput(operationBytes, id)).toString("hex"),
        ).toBe(vector.assertionMlDsa65PopSigningInputHex);
      }
    });
  }
});
