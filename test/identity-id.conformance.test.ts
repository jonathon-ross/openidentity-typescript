import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { IdentityId, IdentityIdError } from "../src/identity-id.js";

interface ValidVector {
  id: string;
  inputHex: string;
  did: string;
}

interface InvalidVector {
  id: string;
  did: string;
  error: string;
}

interface Bundle {
  valid: ValidVector[];
  invalid: InvalidVector[];
}

const bundle = JSON.parse(
  readFileSync(new URL("../protocol/v0.1.1/identity-id-v0.1.json", import.meta.url), "utf8"),
) as Bundle;

describe("Protocol v0.1.1 IdentityId vectors", () => {
  for (const vector of bundle.valid) {
    it(vector.id + " encodes and decodes canonically", () => {
      const id = IdentityId.fromHex(vector.inputHex);
      expect(id.toDid()).toBe(vector.did);
      expect(IdentityId.fromDid(vector.did).toHex()).toBe(vector.inputHex);
    });
  }

  for (const vector of bundle.invalid) {
    it(vector.id + " rejects with " + vector.error, () => {
      try {
        IdentityId.fromDid(vector.did);
        expect.fail("Expected invalid DID");
      } catch (error) {
        expect(error).toBeInstanceOf(IdentityIdError);
        expect((error as IdentityIdError).code).toBe(vector.error);
      }
    });
  }
});
