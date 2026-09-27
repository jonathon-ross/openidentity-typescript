import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { decodeIdentityState } from "../src/state-codec.js";
import { decodeSecuredCredential } from "../src/credential.js";
import {
  ProjectionException,
  projectW3cCredential,
  validateW3cCredentialProjection,
  type W3cCredentialProjection,
} from "../src/w3c-credential-projection.js";

interface ValidVector {
  id: string;
  sourceCredentialVector: string;
  w3cCredential: W3cCredentialProjection;
}
interface InvalidVector {
  id: string;
  sourceProjectionVector: string;
  expectedError: string;
  w3cCredential: W3cCredentialProjection;
  substitutedCurrentIdentityStateHex?: string;
}
interface ProjectionBundle {
  validVectors: ValidVector[];
  invalidVectors: InvalidVector[];
}
interface CredentialVector {
  id: string;
  securedCredentialHex: string;
  historicalIdentityStateHex: string;
}
interface CredentialBundle {
  validVectors: CredentialVector[];
}

const projections = JSON.parse(
  readFileSync(
    new URL("../protocol/v0.1.1/w3c-credential-projection-v0.1.json", import.meta.url),
    "utf8",
  ),
) as ProjectionBundle;
const credentials = JSON.parse(
  readFileSync(new URL("../protocol/v0.1.1/credential-v0.1.json", import.meta.url), "utf8"),
) as CredentialBundle;

function source(id: string): CredentialVector {
  const vector = credentials.validVectors.find((candidate) => candidate.id === id);
  if (vector === undefined) throw new Error("Missing credential vector " + id);
  return vector;
}

describe("Protocol v0.1.1 W3C credential projection", () => {
  for (const vector of projections.validVectors) {
    it(vector.id + " projects exactly from native OI-003", () => {
      const credential = source(vector.sourceCredentialVector);
      const secured = decodeSecuredCredential(
        Uint8Array.from(Buffer.from(credential.securedCredentialHex, "hex")),
      );
      expect(projectW3cCredential(secured)).toEqual(vector.w3cCredential);
    });

    it(vector.id + " validates against historical assertion state", () => {
      const credential = source(vector.sourceCredentialVector);
      const historical = decodeIdentityState(
        Uint8Array.from(Buffer.from(credential.historicalIdentityStateHex, "hex")),
      );
      expect(() => {
        validateW3cCredentialProjection(vector.w3cCredential, historical);
      }).not.toThrow();
    });
  }

  for (const vector of projections.invalidVectors.filter((candidate) => candidate.id !== "WPI10")) {
    it(vector.id + " rejects with " + vector.expectedError, () => {
      const valid = projections.validVectors.find(
        (candidate) => candidate.id === vector.sourceProjectionVector,
      );
      if (valid === undefined) throw new Error("Missing source projection");
      const credential = source(valid.sourceCredentialVector);
      const historical = decodeIdentityState(
        Uint8Array.from(Buffer.from(credential.historicalIdentityStateHex, "hex")),
      );
      try {
        validateW3cCredentialProjection(vector.w3cCredential, historical);
        throw new Error("Expected " + vector.expectedError);
      } catch (error) {
        if (error instanceof ProjectionException) {
          expect(error.code).toBe(vector.expectedError);
          return;
        }
        throw error;
      }
    });
  }
});
