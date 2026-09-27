import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { decodeIdentityState } from "../src/state-codec.js";
import { decodeOperation } from "../src/operation.js";
import { applySetAssertionPolicy, validateStateVersionTransition } from "../src/transitions.js";
import { validationCode } from "../src/errors.js";

interface Vector {
  id: string;
  expectedError: string;
  previousIdentityStateHex: string;
  operationBytesHex: string;
  invalidResultingIdentityStateHex?: string;
}

interface Bundle {
  invalidVectors: Vector[];
}

const bundle = JSON.parse(
  readFileSync(
    new URL("../protocol/v0.1.1/assertion-authority-v0.1.json", import.meta.url),
    "utf8",
  ),
) as Bundle;

describe("remaining frozen assertion-authority invalid vectors", () => {
  for (const vector of bundle.invalidVectors.filter((candidate) =>
    ["AI05", "AI06", "AI08", "AI09"].includes(candidate.id),
  )) {
    it(vector.id + " rejects", () => {
      const current = decodeIdentityState(
        Uint8Array.from(Buffer.from(vector.previousIdentityStateHex, "hex")),
      );
      try {
        const operation = decodeOperation(
          Uint8Array.from(Buffer.from(vector.operationBytesHex, "hex")),
        );
        if (operation.operationType !== 5) throw new Error("Expected SET_ASSERTION_POLICY");
        applySetAssertionPolicy(current, operation);
        throw new Error("Expected " + vector.expectedError);
      } catch (error) {
        expect(validationCode(error) ?? (error instanceof Error ? error.message : undefined)).toBe(
          vector.expectedError,
        );
      }
    });
  }

  const downgrade = bundle.invalidVectors.find((vector) => vector.id === "AI10");
  if (downgrade === undefined) throw new Error("Missing AI10");
  it("AI10 rejects v2 to v1 state downgrade", () => {
    if (downgrade.invalidResultingIdentityStateHex === undefined) {
      throw new Error("Missing invalid resulting state");
    }
    const current = decodeIdentityState(
      Uint8Array.from(Buffer.from(downgrade.previousIdentityStateHex, "hex")),
    );
    const invalid = decodeIdentityState(
      Uint8Array.from(Buffer.from(downgrade.invalidResultingIdentityStateHex, "hex")),
    );
    expect(() => validateStateVersionTransition(current, invalid)).toThrow(
      downgrade.expectedError,
    );
  });
});
