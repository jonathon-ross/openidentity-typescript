import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { Ed25519Key } from "../src/model.js";
import { verifyEd25519 } from "../src/crypto.js";
import { decodeSignedOperation, encodeSignedOperation } from "../src/signed-operation.js";

interface Vector {
  id: string;
  expectedResult: string;
  expectedError?: string;
  signedOperationHex?: string;
  controllerPublicKeyHex?: string;
  authorizationSigningInputHex?: string;
  authorizationSignatureHex?: string;
  originalAuthorizationSignatureHex?: string;
  mutatedSigningInputHex?: string;
  substitutedSignatureHex?: string;
  requiredSigningInputHex?: string;
  authorizationSignatureHex?: string;
}

interface Bundle {
  vectors: Vector[];
}

const bundle = JSON.parse(
  readFileSync(
    new URL("../protocol/v0.1.1/signature-envelope-v0.1.json", import.meta.url),
    "utf8",
  ),
) as Bundle;

const se01 = bundle.vectors.find((vector) => vector.id === "SE01");
if (se01 === undefined) throw new Error("Missing SE01");

describe("Protocol v0.1.1 signature envelope", () => {
  it("SE01 SignedOperation round-trips byte-for-byte", () => {
    if (se01.signedOperationHex === undefined) throw new Error("Missing signed operation");
    const expected = Uint8Array.from(Buffer.from(se01.signedOperationHex, "hex"));
    expect(encodeSignedOperation(decodeSignedOperation(expected))).toEqual(expected);
  });

  it("SE01 Ed25519 ordinary authorization verifies", () => {
    if (
      se01.controllerPublicKeyHex === undefined ||
      se01.authorizationSigningInputHex === undefined ||
      se01.authorizationSignatureHex === undefined
    ) throw new Error("Incomplete SE01");
    expect(
      verifyEd25519(
        new Ed25519Key(Uint8Array.from(Buffer.from(se01.controllerPublicKeyHex, "hex"))),
        Uint8Array.from(Buffer.from(se01.authorizationSigningInputHex, "hex")),
        Uint8Array.from(Buffer.from(se01.authorizationSignatureHex, "hex")),
      ),
    ).toBe(true);
  });

  for (const vector of bundle.vectors.filter((candidate) => candidate.id !== "SE01")) {
    it(vector.id + " rejects the frozen substituted or mutated Ed25519 authorization", () => {
      const signatureHex =
        vector.originalAuthorizationSignatureHex ??
        vector.substitutedSignatureHex ??
        vector.authorizationSignatureHex;
      const inputHex = vector.mutatedSigningInputHex ?? vector.requiredSigningInputHex;
      if (
        signatureHex === undefined ||
        inputHex === undefined ||
        se01.controllerPublicKeyHex === undefined
      ) return;
      expect(
        verifyEd25519(
          new Ed25519Key(Uint8Array.from(Buffer.from(se01.controllerPublicKeyHex, "hex"))),
          Uint8Array.from(Buffer.from(inputHex, "hex")),
          Uint8Array.from(Buffer.from(signatureHex, "hex")),
        ),
      ).toBe(false);
    });
  }
});
