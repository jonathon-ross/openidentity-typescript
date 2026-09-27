import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { MlDsa65Key } from "../src/model.js";
import { verifyMlDsa65 } from "../src/crypto.js";
import { decodeSignedOperation } from "../src/signed-operation.js";
import { verifyAuthorityPolicy } from "../src/policy-verifier.js";
import { decodeOperation, encodeOperationSigningInput } from "../src/operation.js";

interface Vector {
  id: string;
  operationBytesHex: string;
  signedOperationHex: string;
  authorizationSigningInputHex?: string;
  mlDsa65PublicKeyHex?: string;
  mlDsa65SignatureHex?: string;
  oldMlDsa65PublicKeyHex?: string;
  oldMlDsa65AuthorizationSignatureHex?: string;
}

interface Bundle {
  valid: Vector[];
}

const bundle = JSON.parse(
  readFileSync(
    new URL("../protocol/v0.1.1/cryptographic-agility-v0.1.json", import.meta.url),
    "utf8",
  ),
) as Bundle;

const v02 = bundle.valid.find((vector) => vector.id === "V02");
const v04 = bundle.valid.find((vector) => vector.id === "V04");
if (v02 === undefined || v04 === undefined) throw new Error("Missing frozen hybrid vectors V02/V04");

describe("Protocol v0.1.1 hybrid cryptographic verification", () => {
  it("V02 verifies the frozen ML-DSA-65 CREATE authorization signature", () => {
    if (v02.mlDsa65PublicKeyHex === undefined || v02.mlDsa65SignatureHex === undefined) {
      throw new Error("Incomplete V02 ML-DSA fields");
    }
    const operationBytes = Uint8Array.from(Buffer.from(v02.operationBytesHex, "hex"));
    expect(
      verifyMlDsa65(
        new MlDsa65Key(Uint8Array.from(Buffer.from(v02.mlDsa65PublicKeyHex, "hex"))),
        encodeOperationSigningInput(operationBytes),
        Uint8Array.from(Buffer.from(v02.mlDsa65SignatureHex, "hex")),
      ),
    ).toBe(true);
  });

  it("V02 satisfies the frozen hybrid CREATE controller threshold", () => {
    const operationBytes = Uint8Array.from(Buffer.from(v02.operationBytesHex, "hex"));
    const operation = decodeOperation(operationBytes);
    if (operation.operationType !== 1) throw new Error("V02 must be CREATE");
    const signed = decodeSignedOperation(Uint8Array.from(Buffer.from(v02.signedOperationHex, "hex")));
    expect(
      verifyAuthorityPolicy(
        operation.controllerPolicy,
        encodeOperationSigningInput(operationBytes),
        signed.authorizationProofs ?? [],
      ),
    ).toBe(true);
  });

  it("V04 verifies the frozen old-controller ML-DSA-65 authorization signature", () => {
    if (
      v04.oldMlDsa65PublicKeyHex === undefined ||
      v04.oldMlDsa65AuthorizationSignatureHex === undefined ||
      v04.authorizationSigningInputHex === undefined
    ) {
      throw new Error("Incomplete V04 ML-DSA fields");
    }
    expect(
      verifyMlDsa65(
        new MlDsa65Key(Uint8Array.from(Buffer.from(v04.oldMlDsa65PublicKeyHex, "hex"))),
        Uint8Array.from(Buffer.from(v04.authorizationSigningInputHex, "hex")),
        Uint8Array.from(Buffer.from(v04.oldMlDsa65AuthorizationSignatureHex, "hex")),
      ),
    ).toBe(true);
  });
});
