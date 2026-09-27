import { decodeDeterministic, encodeDeterministic } from "./cbor.js";
import type { CborValue } from "./cbor.js";
import { IdentityId } from "./identity-id.js";
import { StateHash } from "./state-hash.js";
import { VerificationMethodId } from "./verification-method-id.js";

export type ClaimValue =
  | bigint
  | string
  | Uint8Array
  | boolean
  | null
  | readonly ClaimValue[]
  | ReadonlyMap<string, ClaimValue>;

export interface OpenIdentityCredential {
  readonly credentialVersion: 1;
  readonly credentialId: Uint8Array;
  readonly issuerIdentity: IdentityId;
  readonly issuanceStateHash: StateHash;
  readonly validFrom: bigint;
  readonly validUntil?: bigint;
  readonly credentialProfile: string;
  readonly credentialSubject: Uint8Array;
  readonly claims: ReadonlyMap<string, ClaimValue>;
}

export interface CredentialProof {
  readonly methodId: VerificationMethodId;
  readonly signature: Uint8Array;
}

export interface SecuredCredential {
  readonly credential: OpenIdentityCredential;
  readonly proofs: readonly CredentialProof[];
}

function map(value: CborValue): ReadonlyMap<CborValue, CborValue> {
  if (!(value instanceof Map)) throw new RangeError("Expected CBOR map");
  return value;
}
function integer(value: CborValue | undefined): bigint {
  if (typeof value !== "bigint") throw new RangeError("Expected CBOR integer");
  return value;
}
function bytes(value: CborValue | undefined): Uint8Array {
  if (!(value instanceof Uint8Array)) throw new RangeError("Expected CBOR byte string");
  return value;
}
function text(value: CborValue | undefined): string {
  if (typeof value !== "string" || value.length === 0)
    throw new RangeError("Expected non-empty text");
  return value;
}
function compare(left: Uint8Array, right: Uint8Array): number {
  for (let i = 0; i < Math.min(left.length, right.length); i += 1) {
    const a = left.at(i);
    const b = right.at(i);
    if (a === undefined || b === undefined) throw new Error("Unexpected bounds");
    if (a !== b) return a - b;
  }
  return left.length - right.length;
}
function claim(value: CborValue): ClaimValue {
  if (
    typeof value === "bigint" ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    value === null ||
    value instanceof Uint8Array
  )
    return value;
  if (Array.isArray(value)) {
    const items: readonly CborValue[] = value;
    return items.map(claim);
  }
  if (value instanceof Map) {
    const entries: ReadonlyMap<CborValue, CborValue> = value;
    const result = new Map<string, ClaimValue>();
    for (const [key, item] of entries) {
      if (typeof key !== "string" || key.length === 0) throw new RangeError("Invalid claim key");
      result.set(key, claim(item));
    }
    return result;
  }
  throw new RangeError("Unsupported claim value");
}
function claims(value: CborValue): ReadonlyMap<string, ClaimValue> {
  const decoded = claim(value);
  if (!(decoded instanceof Map) || decoded.size === 0)
    throw new RangeError("Claims must be non-empty map");
  return decoded;
}
function encodeClaim(value: ClaimValue): CborValue {
  if (value instanceof Map) {
    return new Map<CborValue, CborValue>(
      [...value.entries()].map(([key, item]) => [key, encodeClaim(item)]),
    );
  }
  if (Array.isArray(value)) {
    const items: readonly ClaimValue[] = value;
    return items.map(encodeClaim);
  }
  return value;
}

export function decodeCredential(credentialBytes: Uint8Array): OpenIdentityCredential {
  const root = map(decodeDeterministic(credentialBytes));
  const allowed: readonly bigint[] = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n];
  for (const key of root.keys())
    if (typeof key !== "bigint" || !allowed.includes(key))
      throw new RangeError("Unknown credential field");
  for (const key of [1n, 2n, 3n, 4n, 5n, 7n, 8n, 9n])
    if (!root.has(key)) throw new RangeError("Missing credential field");
  if (integer(root.get(1n)) !== 1n) throw new RangeError("Unsupported credential version");
  const validFrom = integer(root.get(5n));
  const validUntil = root.has(6n) ? integer(root.get(6n)) : undefined;
  if (validUntil !== undefined && validUntil <= validFrom)
    throw new RangeError("INVALID_VALIDITY_PERIOD");
  const credentialId = bytes(root.get(2n));
  if (credentialId.length !== 32) throw new RangeError("Invalid credential ID");
  const subject = bytes(root.get(8n));
  if (subject.length === 0) throw new RangeError("Empty credential subject");
  const base = {
    credentialVersion: 1 as const,
    credentialId: credentialId.slice(),
    issuerIdentity: new IdentityId(bytes(root.get(3n))),
    issuanceStateHash: new StateHash(bytes(root.get(4n))),
    validFrom,
    credentialProfile: text(root.get(7n)),
    credentialSubject: subject.slice(),
    claims: claims(root.get(9n) ?? null),
  };
  return validUntil === undefined ? base : { ...base, validUntil };
}

export function encodeCredential(value: OpenIdentityCredential): Uint8Array {
  if (value.credentialId.length !== 32) throw new RangeError("Invalid credential ID");
  if (value.validUntil !== undefined && value.validUntil <= value.validFrom)
    throw new RangeError("INVALID_VALIDITY_PERIOD");
  if (
    value.credentialProfile.length === 0 ||
    value.credentialSubject.length === 0 ||
    value.claims.size === 0
  )
    throw new RangeError("Invalid credential");
  const root = new Map<CborValue, CborValue>([
    [1n, 1n],
    [2n, value.credentialId],
    [3n, value.issuerIdentity.bytes()],
    [4n, value.issuanceStateHash.bytes()],
    [5n, value.validFrom],
    [7n, value.credentialProfile],
    [8n, value.credentialSubject],
    [9n, encodeClaim(value.claims)],
  ]);
  if (value.validUntil !== undefined) root.set(6n, value.validUntil);
  return encodeDeterministic(root);
}

export function encodeCredentialSigningInput(credentialBytes: Uint8Array): Uint8Array {
  return encodeDeterministic(["OpenIdentity Credential", 1n, credentialBytes]);
}

function decodeProof(value: CborValue): CredentialProof {
  const proof = map(value);
  if (proof.size !== 2 || !proof.has(1n) || !proof.has(2n))
    throw new RangeError("Invalid credential proof");
  return {
    methodId: new VerificationMethodId(bytes(proof.get(1n))),
    signature: bytes(proof.get(2n)),
  };
}

export function decodeSecuredCredential(value: Uint8Array): SecuredCredential {
  const root = map(decodeDeterministic(value));
  if (root.size !== 2 || !root.has(1n) || !root.has(2n))
    throw new RangeError("Invalid secured credential");
  const credentialBytes = encodeDeterministic(root.get(1n) ?? null);
  const raw = root.get(2n);
  if (!Array.isArray(raw) || raw.length === 0) throw new RangeError("Credential proofs required");
  const proofs = raw.map(decodeProof);
  return { credential: decodeCredential(credentialBytes), proofs };
}

export function encodeSecuredCredential(value: SecuredCredential): Uint8Array {
  if (value.proofs.length === 0) throw new RangeError("Credential proofs required");
  const proofs = [...value.proofs].sort((a, b) => compare(a.methodId.bytes(), b.methodId.bytes()));
  return encodeDeterministic(
    new Map<CborValue, CborValue>([
      [1n, decodeDeterministic(encodeCredential(value.credential))],
      [
        2n,
        proofs.map(
          (proof) =>
            new Map<CborValue, CborValue>([
              [1n, proof.methodId.bytes()],
              [2n, proof.signature],
            ]),
        ),
      ],
    ]),
  );
}
