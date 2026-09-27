import { createHash } from "node:crypto";
import { encodeDeterministic } from "./cbor.js";
import type { CborValue } from "./cbor.js";
import type { VerificationMethod } from "./model.js";
import { decodeVerificationMethods } from "./state-codec.js";
import { StateHash } from "./state-hash.js";

export interface RecoveryPolicy {
  readonly threshold: number;
  readonly methods: readonly VerificationMethod[];
}

function map(value: CborValue): ReadonlyMap<CborValue, CborValue> {
  if (!(value instanceof Map)) throw new RangeError("Expected RecoveryPolicy map");
  return value;
}

function integer(value: CborValue | undefined): bigint {
  if (typeof value !== "bigint") throw new RangeError("Expected RecoveryPolicy integer");
  return value;
}

export function decodeRecoveryPolicy(value: CborValue): RecoveryPolicy {
  const policy = map(value);
  if (integer(policy.get(1n)) !== 1n) throw new RangeError("Unsupported recovery policy version");
  const type = integer(policy.get(2n));
  if (type === 1n) {
    if (policy.size !== 3) throw new RangeError("Invalid SINGLE RecoveryPolicy");
    const methods = decodeVerificationMethods(policy.get(3n) ?? null);
    if (methods.length !== 1) throw new RangeError("INVALID_RECOVERY_THRESHOLD");
    return { threshold: 1, methods };
  }
  if (type === 2n) {
    if (policy.size !== 4) throw new RangeError("Invalid THRESHOLD RecoveryPolicy");
    const threshold = Number(integer(policy.get(3n)));
    const methods = decodeVerificationMethods(policy.get(4n) ?? null);
    if (!Number.isSafeInteger(threshold) || threshold < 1 || threshold > methods.length) {
      throw new RangeError("INVALID_RECOVERY_THRESHOLD");
    }
    return { threshold, methods };
  }
  throw new RangeError("Unsupported RecoveryPolicy type");
}

export function encodeRecoveryPolicy(policy: RecoveryPolicy): Uint8Array {
  const methods = policy.methods.map(
    (method) =>
      new Map<CborValue, CborValue>([
        [1n, method.id.bytes()],
        [2n, encodeCoseKey(method)],
      ]),
  );
  if (policy.threshold === 1 && methods.length === 1) {
    return encodeDeterministic(new Map<CborValue, CborValue>([[1n, 1n], [2n, 1n], [3n, methods]]));
  }
  if (policy.threshold < 1 || policy.threshold > methods.length) {
    throw new RangeError("INVALID_RECOVERY_THRESHOLD");
  }
  return encodeDeterministic(
    new Map<CborValue, CborValue>([
      [1n, 1n],
      [2n, 2n],
      [3n, BigInt(policy.threshold)],
      [4n, methods],
    ]),
  );
}

function encodeCoseKey(method: VerificationMethod): CborValue {
  const key = method.key;
  if (key.kind === "Ed25519") {
    return new Map<CborValue, CborValue>([
      [1n, 1n], [3n, -8n], [-1n, 6n], [-2n, key.publicKey()],
    ]);
  }
  return new Map<CborValue, CborValue>([
    [1n, 7n], [3n, -49n], [-1n, key.publicKey()],
  ]);
}

export function recoveryCommitment(policyBytes: Uint8Array): StateHash {
  const digest = createHash("sha256").update(policyBytes).digest();
  return new StateHash(Uint8Array.of(0x12, 0x20, ...digest));
}
