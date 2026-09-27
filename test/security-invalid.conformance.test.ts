import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { decodeIdentityState } from "../src/state-codec.js";
import { decodeSignedOperation } from "../src/signed-operation.js";
import { verifyStatefulSignedOperation } from "../src/verifier.js";
import { OpenIdentityValidationError } from "../src/errors.js";

interface InvalidVector {
  id: string;
  expectedError: string;
  previousIdentityStateHex: string;
  signedOperationHex?: string;
}

interface Bundle {
  invalidVectors: InvalidVector[];
}

function load(name: string): Bundle {
  return JSON.parse(
    readFileSync(new URL("../protocol/v0.1.1/" + name, import.meta.url), "utf8"),
  ) as Bundle;
}

function expectCode(vector: InvalidVector): void {
  if (vector.signedOperationHex === undefined) return;
  const current = decodeIdentityState(
    Uint8Array.from(Buffer.from(vector.previousIdentityStateHex, "hex")),
  );
  try {
    verifyStatefulSignedOperation(
      current,
      decodeSignedOperation(Uint8Array.from(Buffer.from(vector.signedOperationHex, "hex"))),
    );
    throw new Error("Expected " + vector.expectedError);
  } catch (error) {
    if (error instanceof OpenIdentityValidationError) {
      expect(error.code).toBe(vector.expectedError);
      return;
    }
    throw error;
  }
}

describe("frozen invalid assertion-authority security vectors", () => {
  const selected = load("assertion-authority-v0.1.json").invalidVectors.filter((vector) =>
    ["AI01", "AI02", "AI03", "AI04", "AI07"].includes(vector.id),
  );
  for (const vector of selected) {
    it(vector.id + " rejects with " + vector.expectedError, () => {
      expectCode(vector);
    });
  }
});

describe("frozen invalid recovery security vectors", () => {
  const selected = load("recovery-v0.1.json").invalidVectors.filter((vector) =>
    ["RI04", "RI05", "RI06", "RI07", "RI08", "RI09", "RI10"].includes(vector.id),
  );
  for (const vector of selected) {
    it(vector.id + " rejects with " + vector.expectedError, () => expectCode(vector));
  }
});
