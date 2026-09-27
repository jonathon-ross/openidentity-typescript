import { decodeDeterministic, encodeDeterministic } from "./cbor.js";
import type { CborValue } from "./cbor.js";
import { decodeOperation, encodeOperation } from "./operation.js";
import type { OpenIdentityOperation } from "./operation.js";
import { VerificationMethodId } from "./verification-method-id.js";

export interface SignatureProof {
  readonly methodId: VerificationMethodId;
  readonly signature: Uint8Array;
}

export interface SignedOperation {
  readonly operation: OpenIdentityOperation;
  readonly authorizationProofs?: readonly SignatureProof[];
  readonly controllerProofs?: readonly SignatureProof[];
  readonly recoveryProofs?: readonly SignatureProof[];
}

function map(value: CborValue): ReadonlyMap<CborValue, CborValue> {
  if (!(value instanceof Map)) throw new RangeError("Expected CBOR map");
  return value;
}

function array(value: CborValue): readonly CborValue[] {
  if (!Array.isArray(value)) throw new RangeError("Expected CBOR array");
  const items: readonly CborValue[] = value;
  return items;
}

function bytes(value: CborValue | undefined): Uint8Array {
  if (!(value instanceof Uint8Array)) throw new RangeError("Expected CBOR byte string");
  return value;
}

function compare(left: Uint8Array, right: Uint8Array): number {
  for (let index = 0; index < Math.min(left.length, right.length); index += 1) {
    const a = left.at(index);
    const b = right.at(index);
    if (a === undefined || b === undefined) throw new Error("Unexpected byte bounds");
    if (a !== b) return a - b;
  }
  return left.length - right.length;
}

function decodeProof(value: CborValue): SignatureProof {
  const proof = map(value);
  if (proof.size !== 2 || !proof.has(1n) || !proof.has(2n)) {
    throw new RangeError("Invalid signature proof");
  }
  return {
    methodId: new VerificationMethodId(bytes(proof.get(1n))),
    signature: bytes(proof.get(2n)),
  };
}

function decodeProofs(value: CborValue): readonly SignatureProof[] {
  const proofs = array(value).map(decodeProof);
  if (proofs.length === 0) throw new RangeError("Proof collection must not be empty");
  for (let index = 1; index < proofs.length; index += 1) {
    const previous = proofs.at(index - 1);
    const current = proofs.at(index);
    if (previous === undefined || current === undefined) throw new Error("Unexpected proof bounds");
    if (compare(previous.methodId.bytes(), current.methodId.bytes()) >= 0) {
      throw new RangeError("Proofs are not canonically ordered or contain duplicate IDs");
    }
  }
  return proofs;
}

function encodeProofs(proofs: readonly SignatureProof[]): readonly CborValue[] {
  const sorted = [...proofs].sort((a, b) => compare(a.methodId.bytes(), b.methodId.bytes()));
  for (let index = 1; index < sorted.length; index += 1) {
    const previous = sorted.at(index - 1);
    const current = sorted.at(index);
    if (previous === undefined || current === undefined) throw new Error("Unexpected proof bounds");
    if (compare(previous.methodId.bytes(), current.methodId.bytes()) === 0) {
      throw new RangeError("Duplicate proof ID");
    }
  }
  if (sorted.length === 0) throw new RangeError("Proof collection must not be empty");
  return sorted.map(
    (proof) =>
      new Map<CborValue, CborValue>([
        [1n, proof.methodId.bytes()],
        [2n, proof.signature],
      ]),
  );
}

export function decodeSignedOperation(bytesValue: Uint8Array): SignedOperation {
  const root = map(decodeDeterministic(bytesValue));
  for (const key of root.keys()) {
    if (typeof key !== "bigint" || key < 1n || key > 4n) {
      throw new RangeError("UNSUPPORTED_PROTOCOL_FEATURE");
    }
  }
  if (!root.has(1n)) throw new RangeError("Missing operation");
  const operationBytes = encodeDeterministic(root.get(1n) ?? null);
  const result: SignedOperation = { operation: decodeOperation(operationBytes) };
  return {
    ...result,
    ...(root.has(2n) ? { authorizationProofs: decodeProofs(root.get(2n) ?? null) } : {}),
    ...(root.has(3n) ? { controllerProofs: decodeProofs(root.get(3n) ?? null) } : {}),
    ...(root.has(4n) ? { recoveryProofs: decodeProofs(root.get(4n) ?? null) } : {}),
  };
}

export function encodeSignedOperation(value: SignedOperation): Uint8Array {
  const operation = decodeDeterministic(encodeOperation(value.operation));
  const root = new Map<CborValue, CborValue>([[1n, operation]]);
  if (value.authorizationProofs !== undefined)
    root.set(2n, encodeProofs(value.authorizationProofs));
  if (value.controllerProofs !== undefined) root.set(3n, encodeProofs(value.controllerProofs));
  if (value.recoveryProofs !== undefined) root.set(4n, encodeProofs(value.recoveryProofs));
  return encodeDeterministic(root);
}
