import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  decodeCredential,
  decodeSecuredCredential,
  encodeCredential,
  encodeCredentialSigningInput,
  encodeSecuredCredential,
} from "../src/credential.js";
import { decodeIdentityState } from "../src/state-codec.js";
import {
  CredentialVerificationException,
  verifyCredentialAgainstHistoricalState,
} from "../src/credential-verifier.js";

interface ValidVector {
  id: string;
  credentialBytesHex: string;
  credentialSigningInputHex: string;
  historicalIdentityStateHex: string;
  securedCredentialHex: string;
}
interface InvalidVector {
  id: string;
  expectedError: string;
  historicalIdentityStateHex: string;
  securedCredentialHex: string;
}
interface Bundle {
  validVectors: ValidVector[];
  invalidVectors: InvalidVector[];
}

const bundle = JSON.parse(
  readFileSync(new URL("../protocol/v0.1.1/credential-v0.1.json", import.meta.url), "utf8"),
) as Bundle;

describe("Protocol v0.1.1 OI-003 credentials", () => {
  for (const vector of bundle.validVectors) {
    it(vector.id + " round-trips credential and secured credential byte-for-byte", () => {
      const credentialBytes = Uint8Array.from(Buffer.from(vector.credentialBytesHex, "hex"));
      expect(encodeCredential(decodeCredential(credentialBytes))).toEqual(credentialBytes);
      expect(Buffer.from(encodeCredentialSigningInput(credentialBytes)).toString("hex")).toBe(
        vector.credentialSigningInputHex,
      );
      const securedBytes = Uint8Array.from(Buffer.from(vector.securedCredentialHex, "hex"));
      expect(encodeSecuredCredential(decodeSecuredCredential(securedBytes))).toEqual(securedBytes);
    });

    it(vector.id + " verifies against exact historical AssertionPolicy", () => {
      const secured = decodeSecuredCredential(
        Uint8Array.from(Buffer.from(vector.securedCredentialHex, "hex")),
      );
      const historical = decodeIdentityState(
        Uint8Array.from(Buffer.from(vector.historicalIdentityStateHex, "hex")),
      );
      expect(() => {
        verifyCredentialAgainstHistoricalState(secured, historical);
      }).not.toThrow();
    });
  }

  for (const vector of bundle.invalidVectors) {
    it(vector.id + " rejects with " + vector.expectedError, () => {
      const historical = decodeIdentityState(
        Uint8Array.from(Buffer.from(vector.historicalIdentityStateHex, "hex")),
      );
      try {
        verifyCredentialAgainstHistoricalState(
          decodeSecuredCredential(Uint8Array.from(Buffer.from(vector.securedCredentialHex, "hex"))),
          historical,
        );
        throw new Error("Expected " + vector.expectedError);
      } catch (error) {
        if (error instanceof CredentialVerificationException) {
          expect(error.code).toBe(vector.expectedError);
          return;
        }
        throw error;
      }
    });
  }
});
