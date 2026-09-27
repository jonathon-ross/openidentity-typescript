import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { StateHash } from "../src/state-hash.js";
import { decodeIdentityState, encodeIdentityState } from "../src/state-codec.js";
import { decodeOperation, encodeOperation, encodeOperationSigningInput } from "../src/operation.js";
import { applyDeactivate } from "../src/transitions.js";
import { encodeDeterministic } from "../src/cbor.js";
import type { CborValue } from "../src/cbor.js";

interface StateVector {
  id: string;
  stateBytesHex: string;
}

interface StateBundle {
  vectors: StateVector[];
}

const states = JSON.parse(
  readFileSync(new URL("../protocol/v0.1.1/state-hash-v0.1.json", import.meta.url), "utf8"),
) as StateBundle;

const source = states.vectors[0];
if (source === undefined) throw new Error("Missing frozen state vector");

describe("OI-006 DEACTIVATE state-machine scenarios", () => {
  it("D01 deactivates an ACTIVE state while preserving its version and policies", () => {
    const previousBytes = Uint8Array.from(Buffer.from(source.stateBytesHex, "hex"));
    const previous = decodeIdentityState(previousBytes);
    const previousHash = StateHash.fromStateBytes(previousBytes);
    const operationBytes = encodeDeterministic(
      new Map<CborValue, CborValue>([
        [1n, 1n],
        [2n, 4n],
        [3n, previous.identity.bytes()],
        [4n, previous.sequence + 1n],
        [5n, previousHash.bytes()],
        [6n, new Map<CborValue, CborValue>()],
      ]),
    );

    const operation = decodeOperation(operationBytes);
    expect(operation.operationType).toBe(4);
    if (operation.operationType !== 4) throw new Error("Expected DEACTIVATE");
    expect(encodeOperation(operation)).toEqual(operationBytes);
    expect(encodeOperationSigningInput(operationBytes)).toEqual(
      encodeDeterministic(["OpenIdentity Operation", 1n, operationBytes]),
    );

    const resulting = applyDeactivate(previous, operation);
    expect(resulting.stateVersion).toBe(previous.stateVersion);
    expect(resulting.sequence).toBe(previous.sequence + 1n);
    expect(resulting.status).toBe(2n);
    expect(resulting.identity.equals(previous.identity)).toBe(true);
    expect(encodeIdentityState(resulting)).not.toEqual(previousBytes);
  });

  it("DI01 rejects repeated deactivation", () => {
    const previousBytes = Uint8Array.from(Buffer.from(source.stateBytesHex, "hex"));
    const active = decodeIdentityState(previousBytes);
    const firstBytes = encodeDeterministic(
      new Map<CborValue, CborValue>([
        [1n, 1n],
        [2n, 4n],
        [3n, active.identity.bytes()],
        [4n, active.sequence + 1n],
        [5n, StateHash.fromStateBytes(previousBytes).bytes()],
        [6n, new Map<CborValue, CborValue>()],
      ]),
    );
    const first = decodeOperation(firstBytes);
    if (first.operationType !== 4) throw new Error("Expected DEACTIVATE");
    const deactivated = applyDeactivate(active, first);

    const secondBytes = encodeDeterministic(
      new Map<CborValue, CborValue>([
        [1n, 1n],
        [2n, 4n],
        [3n, deactivated.identity.bytes()],
        [4n, deactivated.sequence + 1n],
        [5n, StateHash.fromStateBytes(encodeIdentityState(deactivated)).bytes()],
        [6n, new Map<CborValue, CborValue>()],
      ]),
    );
    const second = decodeOperation(secondBytes);
    if (second.operationType !== 4) throw new Error("Expected DEACTIVATE");
    expect(() => applyDeactivate(deactivated, second)).toThrow("IDENTITY_DEACTIVATED");
  });
});
