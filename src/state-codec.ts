import { decodeDeterministic, encodeDeterministic } from "./cbor.js";
import type { CborValue } from "./cbor.js";
import { IdentityId } from "./identity-id.js";
import {
  Ed25519Key,
  MlDsa65Key,
  type AuthorityPolicy,
  type CoseKey,
  type IdentityState,
  type VerificationMethod,
} from "./model.js";
import { VerificationMethodId } from "./verification-method-id.js";

function map(value: CborValue): ReadonlyMap<CborValue, CborValue> {
  if (!(value instanceof Map)) throw new RangeError("Expected CBOR map");
  return value;
}

function array(value: CborValue): readonly CborValue[] {
  if (!Array.isArray(value)) throw new RangeError("Expected CBOR array");
  const items: readonly CborValue[] = value;
  return items;
}

function integer(value: CborValue | undefined): bigint {
  if (typeof value !== "bigint") throw new RangeError("Expected CBOR integer");
  return value;
}

function bytes(value: CborValue | undefined): Uint8Array {
  if (!(value instanceof Uint8Array)) throw new RangeError("Expected CBOR byte string");
  return value;
}

function exactKeys(value: ReadonlyMap<CborValue, CborValue>, keys: readonly bigint[]): void {
  if (value.size !== keys.length) throw new RangeError("Unexpected CBOR map fields");
  for (const key of keys) if (!value.has(key)) throw new RangeError("Missing CBOR map field");
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const a = left.at(index);
    const b = right.at(index);
    if (a === undefined || b === undefined) throw new Error("Unexpected byte bounds");
    if (a !== b) return a - b;
  }
  return left.length - right.length;
}

function decodeKey(value: CborValue): CoseKey {
  const key = map(value);
  const kty = integer(key.get(1n));
  const alg = integer(key.get(3n));
  if (kty === 1n && alg === -8n) {
    exactKeys(key, [1n, 3n, -1n, -2n]);
    if (integer(key.get(-1n)) !== 6n) throw new RangeError("Unsupported OKP curve");
    return new Ed25519Key(bytes(key.get(-2n)));
  }
  if (kty === 7n && alg === -49n) {
    exactKeys(key, [1n, 3n, -1n]);
    return new MlDsa65Key(bytes(key.get(-1n)));
  }
  throw new RangeError("Unsupported OpenIdentity v0.1 COSE key");
}

function encodeKey(key: CoseKey): ReadonlyMap<CborValue, CborValue> {
  if (key instanceof Ed25519Key) {
    return new Map<CborValue, CborValue>([
      [1n, 1n],
      [3n, -8n],
      [-1n, 6n],
      [-2n, key.publicKey()],
    ]);
  }
  return new Map<CborValue, CborValue>([
    [1n, 7n],
    [3n, -49n],
    [-1n, key.publicKey()],
  ]);
}

function decodeMethod(value: CborValue): VerificationMethod {
  const method = map(value);
  exactKeys(method, [1n, 2n]);
  return {
    id: new VerificationMethodId(bytes(method.get(1n))),
    key: decodeKey(method.get(2n) ?? null),
  };
}

function encodeMethod(method: VerificationMethod): ReadonlyMap<CborValue, CborValue> {
  return new Map<CborValue, CborValue>([
    [1n, method.id.bytes()],
    [2n, encodeKey(method.key)],
  ]);
}

function decodeMethods(value: CborValue): readonly VerificationMethod[] {
  const methods = array(value).map(decodeMethod);
  if (methods.length === 0) throw new RangeError("Policy methods must not be empty");
  for (let index = 1; index < methods.length; index += 1) {
    const previous = methods.at(index - 1);
    const current = methods.at(index);
    if (previous === undefined || current === undefined)
      throw new Error("Unexpected method bounds");
    if (compareBytes(previous.id.bytes(), current.id.bytes()) >= 0) {
      throw new RangeError("Verification methods are not canonically ordered");
    }
  }
  return methods;
}

export function decodeAuthorityPolicy(value: CborValue): AuthorityPolicy {
  const policy = map(value);
  const type = integer(policy.get(1n));
  if (type === 1n) {
    exactKeys(policy, [1n, 2n]);
    const methods = decodeMethods(policy.get(2n) ?? null);
    if (methods.length !== 1) throw new RangeError("SINGLE policy requires exactly one method");
    return { threshold: 1, methods };
  }
  if (type === 2n) {
    exactKeys(policy, [1n, 2n, 3n]);
    const threshold = Number(integer(policy.get(2n)));
    const methods = decodeMethods(policy.get(3n) ?? null);
    if (!Number.isSafeInteger(threshold) || threshold < 1 || threshold > methods.length) {
      throw new RangeError("Invalid policy threshold");
    }
    return { threshold, methods };
  }
  throw new RangeError("Unsupported authority policy type");
}

export function encodeAuthorityPolicy(policy: AuthorityPolicy): ReadonlyMap<CborValue, CborValue> {
  if (!Number.isSafeInteger(policy.threshold) || policy.threshold < 1) {
    throw new RangeError("Invalid policy threshold");
  }
  const methods = [...policy.methods].sort((a, b) => compareBytes(a.id.bytes(), b.id.bytes()));
  if (methods.length === 0 || policy.threshold > methods.length) {
    throw new RangeError("Invalid policy");
  }
  for (let index = 1; index < methods.length; index += 1) {
    const previous = methods.at(index - 1);
    const current = methods.at(index);
    if (previous === undefined || current === undefined)
      throw new Error("Unexpected method bounds");
    if (compareBytes(previous.id.bytes(), current.id.bytes()) === 0) {
      throw new RangeError("Duplicate verification method ID");
    }
  }
  const encoded = methods.map(encodeMethod);
  if (policy.threshold === 1 && methods.length === 1) {
    return new Map<CborValue, CborValue>([
      [1n, 1n],
      [2n, encoded],
    ]);
  }
  return new Map<CborValue, CborValue>([
    [1n, 2n],
    [2n, BigInt(policy.threshold)],
    [3n, encoded],
  ]);
}

export function decodeIdentityState(stateBytes: Uint8Array): IdentityState {
  const state = map(decodeDeterministic(stateBytes));
  const version = integer(state.get(1n));
  const allowed = version === 1n ? [1n, 2n, 3n, 4n, 5n, 6n] : [1n, 2n, 3n, 4n, 5n, 6n, 7n];
  for (const key of state.keys()) {
    if (typeof key !== "bigint" || !allowed.includes(key))
      throw new RangeError("Unknown IdentityState field");
  }
  for (const required of [1n, 2n, 3n, 4n, 5n]) {
    if (!state.has(required)) throw new RangeError("Missing IdentityState field");
  }

  const common = {
    identity: new IdentityId(bytes(state.get(2n))),
    sequence: integer(state.get(3n)),
    status: integer(state.get(4n)),
    controllerPolicy: decodeAuthorityPolicy(state.get(5n) ?? null),
  };
  const recoveryCommitment = state.has(6n) ? bytes(state.get(6n)) : undefined;

  if (version === 1n) {
    return recoveryCommitment === undefined
      ? { stateVersion: 1, ...common }
      : { stateVersion: 1, ...common, recoveryCommitment };
  }
  if (version === 2n) {
    const assertionPolicy = state.has(7n) ? decodeAuthorityPolicy(state.get(7n) ?? null) : undefined;
    return {
      stateVersion: 2,
      ...common,
      ...(recoveryCommitment === undefined ? {} : { recoveryCommitment }),
      ...(assertionPolicy === undefined ? {} : { assertionPolicy }),
    };
  }
  throw new RangeError("Unsupported IdentityState version");
}

export function encodeIdentityState(state: IdentityState): Uint8Array {
  const fields = new Map<CborValue, CborValue>([
    [1n, BigInt(state.stateVersion)],
    [2n, state.identity.bytes()],
    [3n, state.sequence],
    [4n, state.status],
    [5n, encodeAuthorityPolicy(state.controllerPolicy)],
  ]);
  if (state.recoveryCommitment !== undefined) fields.set(6n, state.recoveryCommitment);
  if (state.stateVersion === 2 && state.assertionPolicy !== undefined) {
    fields.set(7n, encodeAuthorityPolicy(state.assertionPolicy));
  }
  return encodeDeterministic(fields);
}
