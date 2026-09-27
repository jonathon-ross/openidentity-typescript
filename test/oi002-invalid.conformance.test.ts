import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { decodeOperation } from "../src/operation.js";
import { decodeSignedOperation } from "../src/signed-operation.js";
import { verifyCreateSignedOperation } from "../src/verifier.js";
import { validationCode } from "../src/errors.js";

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
    ["I01", "I02", "I03", "I04", "I05", "I18", "I19"].includes(candidate.id),
  )) {
    it(vector.id + " rejects structurally", () => {
      try {
        decodeOperation(Uint8Array.from(Buffer.from(vector.operationBytesHex, "hex")));
        throw new Error("Expected " + vector.expectedError);
      } catch (error) {
        expect(validationCode(error) ?? (error instanceof Error ? error.message : undefined)).toBe(
          vector.expectedError,
        );
      }
    });
  }


  const supersededRecover = bundle.invalid.find((vector) => vector.id === "I20");
  if (supersededRecover === undefined) throw new Error("Missing historical I20 vector");

  it("I20 is superseded by OI-007 RECOVER assignment", () => {
    expect(supersededRecover.expectedError).toBe("UNSUPPORTED_OPERATION");
    expect(() => {
      decodeOperation(
        Uint8Array.from(Buffer.from(supersededRecover.operationBytesHex, "hex")),
      );
    }).toThrow("Unexpected CBOR map fields");
  });

  for (const vector of bundle.invalid.filter((candidate) =>
    ["I06", "I07", "I08", "I09", "I10"].includes(candidate.id),
  )) {
    it(vector.id + " rejects CREATE authorization", () => {
      const signedOperationHex = vector.signedOperationHex;
      if (signedOperationHex === undefined) throw new Error("Missing SignedOperation");
      try {
        verifyCreateSignedOperation(
          decodeSignedOperation(Uint8Array.from(Buffer.from(signedOperationHex, "hex"))),
        );
        throw new Error("Expected " + vector.expectedError);
      } catch (error) {
        expect(validationCode(error) ?? (error instanceof Error ? error.message : undefined)).toBe(
          vector.expectedError,
        );
      }
    });
  }
});
