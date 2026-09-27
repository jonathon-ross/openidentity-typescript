import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { StateHash } from "../src/state-hash.js";
import { decodeIdentityState, encodeIdentityState } from "../src/state-codec.js";
import {
  decodeOperation,
  encodeControllerProofSigningInput,
  encodeOperation,
  encodeRecoverySigningInput,
} from "../src/operation.js";
import { applyRecover } from "../src/transitions.js";
import { VerificationMethodId } from "../src/verification-method-id.js";

interface Vector {
  id: string;
  operationBytesHex: string;
  previousIdentityStateHex: string;
  resultingIdentityStateHex: string;
  resultingStateHashHex: string;
  currentRecoveryEd25519MethodIdHex: string;
  currentRecoveryMlDsa65MethodIdHex: string;
  recoveryEd25519SigningInputHex: string;
  recoveryMlDsa65SigningInputHex: string;
  newControllerMethodIdHex: string;
  newControllerPopSigningInputHex: string;
}

interface Bundle {
  validVectors: Vector[];
}

const bundle = JSON.parse(
  readFileSync(new URL("../protocol/v0.1.1/recovery-v0.1.json", import.meta.url), "utf8"),
) as Bundle;

describe("Protocol v0.1.1 RECOVER", () => {
  for (const vector of bundle.validVectors) {
    it(vector.id + " round-trips and derives exact resulting state", () => {
      const operationBytes = Uint8Array.from(Buffer.from(vector.operationBytesHex, "hex"));
      const operation = decodeOperation(operationBytes);
      expect(operation.operationType).toBe(3);
      if (operation.operationType !== 3) throw new Error("Expected RECOVER");
      expect(encodeOperation(operation)).toEqual(operationBytes);

      const previous = decodeIdentityState(
        Uint8Array.from(Buffer.from(vector.previousIdentityStateHex, "hex")),
      );
      const resulting = applyRecover(previous, operation);
      const stateBytes = encodeIdentityState(resulting);
      expect(Buffer.from(stateBytes).toString("hex")).toBe(vector.resultingIdentityStateHex);
      expect(StateHash.fromStateBytes(stateBytes).toHex()).toBe(vector.resultingStateHashHex);
    });

    it(vector.id + " reconstructs recovery and new-controller PoP signing inputs", () => {
      const operationBytes = Uint8Array.from(Buffer.from(vector.operationBytesHex, "hex"));
      const ed = VerificationMethodId.fromHex(vector.currentRecoveryEd25519MethodIdHex);
      const ml = VerificationMethodId.fromHex(vector.currentRecoveryMlDsa65MethodIdHex);
      const controller = VerificationMethodId.fromHex(vector.newControllerMethodIdHex);
      expect(Buffer.from(encodeRecoverySigningInput(operationBytes, ed)).toString("hex")).toBe(
        vector.recoveryEd25519SigningInputHex,
      );
      expect(Buffer.from(encodeRecoverySigningInput(operationBytes, ml)).toString("hex")).toBe(
        vector.recoveryMlDsa65SigningInputHex,
      );
      expect(Buffer.from(encodeControllerProofSigningInput(operationBytes, controller)).toString("hex")).toBe(
        vector.newControllerPopSigningInputHex,
      );
    });
  }
});
