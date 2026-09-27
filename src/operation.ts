import { decodeDeterministic, encodeDeterministic } from "./cbor.js";
import type { CborValue } from "./cbor.js";
import { IdentityId } from "./identity-id.js";
import { StateHash } from "./state-hash.js";
import { VerificationMethodId } from "./verification-method-id.js";
import type { AuthorityPolicy } from "./model.js";
import type { RecoveryPolicy } from "./recovery.js";
import { decodeRecoveryPolicy, encodeRecoveryPolicy } from "./recovery.js";
import {
  decodeAssertionPolicy,
  decodeControllerPolicy,
  encodeAuthorityPolicy,
} from "./state-codec.js";
import { OpenIdentityValidationError } from "./errors.js";

export interface RotateControllerOperation {
  readonly protocolVersion: 1;
  readonly operationType: 2;
  readonly identity: IdentityId;
  readonly sequence: bigint;
  readonly previousStateHash: StateHash;
  readonly controllerPolicy: AuthorityPolicy;
}

export interface RecoverOperation {
  readonly protocolVersion: 1;
  readonly operationType: 3;
  readonly identity: IdentityId;
  readonly sequence: bigint;
  readonly previousStateHash: StateHash;
  readonly controllerPolicy: AuthorityPolicy;
  readonly currentRecoveryPolicy: RecoveryPolicy;
  readonly newRecoveryCommitment: StateHash;
}

export interface DeactivateOperation {
  readonly protocolVersion: 1;
  readonly operationType: 4;
  readonly identity: IdentityId;
  readonly sequence: bigint;
  readonly previousStateHash: StateHash;
}

export interface SetAssertionPolicyOperation {
  readonly protocolVersion: 1;
  readonly operationType: 5;
  readonly identity: IdentityId;
  readonly sequence: bigint;
  readonly previousStateHash: StateHash;
  readonly assertionPolicy: AuthorityPolicy | null;
}

export type OpenIdentityOperation =
  | CreateOperation
  | RotateControllerOperation
  | RecoverOperation
  | DeactivateOperation
  | SetAssertionPolicyOperation;

export interface CreateOperation {
  readonly protocolVersion: 1;
  readonly operationType: 1;
  readonly identity: IdentityId;
  readonly sequence: 1n;
  readonly previousStateHash: null;
  readonly controllerPolicy: AuthorityPolicy;
  readonly recoveryCommitment?: Uint8Array;
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

function requireKeys(value: ReadonlyMap<CborValue, CborValue>, keys: readonly bigint[]): void {
  if (value.size !== keys.length) throw new RangeError("Unexpected CBOR map fields");
  for (const key of keys) if (!value.has(key)) throw new RangeError("Missing CBOR map field");
}

export function decodeCreateOperation(operationBytes: Uint8Array): CreateOperation {
  const operation = map(decodeDeterministic(operationBytes));
  requireKeys(operation, [1n, 2n, 3n, 4n, 5n, 6n]);

  if (integer(operation.get(1n)) !== 1n) throw new RangeError("Unsupported protocol version");
  if (integer(operation.get(2n)) !== 1n) throw new RangeError("Operation is not CREATE");
  if (integer(operation.get(4n)) !== 1n) throw new RangeError("INVALID_SEQUENCE");
  if (operation.get(5n) !== null) throw new RangeError("INVALID_PREVIOUS_STATE_HASH");

  const payload = map(operation.get(6n) ?? null);
  if (!payload.has(1n) || payload.size < 1 || payload.size > 2) {
    throw new RangeError("Invalid CREATE payload");
  }
  for (const key of payload.keys()) {
    if (key !== 1n && key !== 2n) throw new RangeError("Unknown CREATE payload field");
  }

  const base = {
    protocolVersion: 1 as const,
    operationType: 1 as const,
    identity: new IdentityId(bytes(operation.get(3n))),
    sequence: 1n as const,
    previousStateHash: null,
    controllerPolicy: decodeControllerPolicy(payload.get(1n) ?? null),
  };
  return payload.has(2n) ? { ...base, recoveryCommitment: bytes(payload.get(2n)) } : base;
}

export function encodeCreateOperation(operation: CreateOperation): Uint8Array {
  const payload = new Map<CborValue, CborValue>([
    [1n, encodeAuthorityPolicy(operation.controllerPolicy)],
  ]);
  if (operation.recoveryCommitment !== undefined) payload.set(2n, operation.recoveryCommitment);

  return encodeDeterministic(
    new Map<CborValue, CborValue>([
      [1n, 1n],
      [2n, 1n],
      [3n, operation.identity.bytes()],
      [4n, 1n],
      [5n, null],
      [6n, payload],
    ]),
  );
}

export function encodeOperationSigningInput(operationBytes: Uint8Array): Uint8Array {
  return encodeDeterministic(["OpenIdentity Operation", 1n, operationBytes]);
}

export function decodeRotateControllerOperation(
  operationBytes: Uint8Array,
): RotateControllerOperation {
  const operation = map(decodeDeterministic(operationBytes));
  requireKeys(operation, [1n, 2n, 3n, 4n, 5n, 6n]);

  if (integer(operation.get(1n)) !== 1n) throw new RangeError("Unsupported protocol version");
  if (integer(operation.get(2n)) !== 2n) throw new RangeError("Operation is not ROTATE_CONTROLLER");
  const sequence = integer(operation.get(4n));
  if (sequence < 2n) throw new RangeError("INVALID_SEQUENCE");

  const payload = map(operation.get(6n) ?? null);
  requireKeys(payload, [1n]);

  return {
    protocolVersion: 1,
    operationType: 2,
    identity: new IdentityId(bytes(operation.get(3n))),
    sequence,
    previousStateHash: new StateHash(bytes(operation.get(5n))),
    controllerPolicy: decodeControllerPolicy(payload.get(1n) ?? null),
  };
}

export function encodeRotateControllerOperation(operation: RotateControllerOperation): Uint8Array {
  if (operation.sequence < 2n) throw new RangeError("INVALID_SEQUENCE");
  return encodeDeterministic(
    new Map<CborValue, CborValue>([
      [1n, 1n],
      [2n, 2n],
      [3n, operation.identity.bytes()],
      [4n, operation.sequence],
      [5n, operation.previousStateHash.bytes()],
      [
        6n,
        new Map<CborValue, CborValue>([[1n, encodeAuthorityPolicy(operation.controllerPolicy)]]),
      ],
    ]),
  );
}

export function decodeOperation(operationBytes: Uint8Array): OpenIdentityOperation {
  const root = map(decodeDeterministic(operationBytes));
  const required = [1n, 2n, 3n, 4n, 5n, 6n] as const;
  for (const key of root.keys()) {
    if (typeof key !== "bigint" || !required.includes(key)) {
      throw new OpenIdentityValidationError("UNSUPPORTED_PROTOCOL_FEATURE");
    }
  }
  for (const key of required) {
    if (!root.has(key)) throw new RangeError("Missing CBOR map field");
  }

  const type = integer(root.get(2n));
  if (type === 1n) return decodeCreateOperation(operationBytes);
  if (type === 2n) return decodeRotateControllerOperation(operationBytes);
  if (type === 3n) return decodeRecoverOperation(operationBytes);
  if (type === 4n) return decodeDeactivateOperation(operationBytes);
  if (type === 5n) return decodeSetAssertionPolicyOperation(operationBytes);
  throw new OpenIdentityValidationError("UNSUPPORTED_OPERATION");
}

export function encodeOperation(operation: OpenIdentityOperation): Uint8Array {
  switch (operation.operationType) {
    case 1:
      return encodeCreateOperation(operation);
    case 2:
      return encodeRotateControllerOperation(operation);
    case 3:
      return encodeRecoverOperation(operation);
    case 4:
      return encodeDeactivateOperation(operation);
    case 5:
      return encodeSetAssertionPolicyOperation(operation);
  }
}

export function encodeControllerProofSigningInput(
  operationBytes: Uint8Array,
  methodId: VerificationMethodId,
): Uint8Array {
  return encodeDeterministic([
    "OpenIdentity Controller Proof",
    1n,
    operationBytes,
    methodId.bytes(),
  ]);
}

export function decodeSetAssertionPolicyOperation(
  operationBytes: Uint8Array,
): SetAssertionPolicyOperation {
  const operation = map(decodeDeterministic(operationBytes));
  requireKeys(operation, [1n, 2n, 3n, 4n, 5n, 6n]);
  if (integer(operation.get(1n)) !== 1n) throw new RangeError("Unsupported protocol version");
  if (integer(operation.get(2n)) !== 5n)
    throw new RangeError("Operation is not SET_ASSERTION_POLICY");
  const sequence = integer(operation.get(4n));
  if (sequence < 2n) throw new RangeError("INVALID_SEQUENCE");
  const payload = map(operation.get(6n) ?? null);
  requireKeys(payload, [1n]);
  const policyValue = payload.get(1n);
  return {
    protocolVersion: 1,
    operationType: 5,
    identity: new IdentityId(bytes(operation.get(3n))),
    sequence,
    previousStateHash: new StateHash(bytes(operation.get(5n))),
    assertionPolicy: policyValue === null ? null : decodeAssertionPolicy(policyValue ?? null),
  };
}

export function encodeSetAssertionPolicyOperation(
  operation: SetAssertionPolicyOperation,
): Uint8Array {
  if (operation.sequence < 2n) throw new RangeError("INVALID_SEQUENCE");
  const policy: CborValue =
    operation.assertionPolicy === null ? null : encodeAuthorityPolicy(operation.assertionPolicy);
  return encodeDeterministic(
    new Map<CborValue, CborValue>([
      [1n, 1n],
      [2n, 5n],
      [3n, operation.identity.bytes()],
      [4n, operation.sequence],
      [5n, operation.previousStateHash.bytes()],
      [6n, new Map<CborValue, CborValue>([[1n, policy]])],
    ]),
  );
}

export function decodeDeactivateOperation(operationBytes: Uint8Array): DeactivateOperation {
  const operation = map(decodeDeterministic(operationBytes));
  requireKeys(operation, [1n, 2n, 3n, 4n, 5n, 6n]);
  if (integer(operation.get(1n)) !== 1n) throw new RangeError("Unsupported protocol version");
  if (integer(operation.get(2n)) !== 4n) throw new RangeError("Operation is not DEACTIVATE");
  const sequence = integer(operation.get(4n));
  if (sequence < 2n) throw new RangeError("INVALID_SEQUENCE");
  const payload = map(operation.get(6n) ?? null);
  if (payload.size !== 0) throw new RangeError("DEACTIVATE payload must be empty");
  return {
    protocolVersion: 1,
    operationType: 4,
    identity: new IdentityId(bytes(operation.get(3n))),
    sequence,
    previousStateHash: new StateHash(bytes(operation.get(5n))),
  };
}

export function encodeDeactivateOperation(operation: DeactivateOperation): Uint8Array {
  if (operation.sequence < 2n) throw new RangeError("INVALID_SEQUENCE");
  return encodeDeterministic(
    new Map<CborValue, CborValue>([
      [1n, 1n],
      [2n, 4n],
      [3n, operation.identity.bytes()],
      [4n, operation.sequence],
      [5n, operation.previousStateHash.bytes()],
      [6n, new Map<CborValue, CborValue>()],
    ]),
  );
}

export function decodeRecoverOperation(operationBytes: Uint8Array): RecoverOperation {
  const operation = map(decodeDeterministic(operationBytes));
  requireKeys(operation, [1n, 2n, 3n, 4n, 5n, 6n]);
  if (integer(operation.get(1n)) !== 1n) throw new RangeError("Unsupported protocol version");
  if (integer(operation.get(2n)) !== 3n) throw new RangeError("Operation is not RECOVER");
  const sequence = integer(operation.get(4n));
  if (sequence < 2n) throw new RangeError("INVALID_SEQUENCE");
  const payload = map(operation.get(6n) ?? null);
  requireKeys(payload, [1n, 2n, 3n]);
  return {
    protocolVersion: 1,
    operationType: 3,
    identity: new IdentityId(bytes(operation.get(3n))),
    sequence,
    previousStateHash: new StateHash(bytes(operation.get(5n))),
    controllerPolicy: decodeControllerPolicy(payload.get(1n) ?? null),
    currentRecoveryPolicy: decodeRecoveryPolicy(payload.get(2n) ?? null),
    newRecoveryCommitment: new StateHash(bytes(payload.get(3n))),
  };
}

export function encodeRecoverOperation(operation: RecoverOperation): Uint8Array {
  if (operation.sequence < 2n) throw new RangeError("INVALID_SEQUENCE");
  const recoveryPolicyBytes = encodeRecoveryPolicy(operation.currentRecoveryPolicy);
  return encodeDeterministic(
    new Map<CborValue, CborValue>([
      [1n, 1n],
      [2n, 3n],
      [3n, operation.identity.bytes()],
      [4n, operation.sequence],
      [5n, operation.previousStateHash.bytes()],
      [
        6n,
        new Map<CborValue, CborValue>([
          [1n, encodeAuthorityPolicy(operation.controllerPolicy)],
          [2n, decodeDeterministic(recoveryPolicyBytes)],
          [3n, operation.newRecoveryCommitment.bytes()],
        ]),
      ],
    ]),
  );
}

export function encodeRecoverySigningInput(
  operationBytes: Uint8Array,
  methodId: VerificationMethodId,
): Uint8Array {
  return encodeDeterministic(["OpenIdentity Recovery", 1n, operationBytes, methodId.bytes()]);
}
