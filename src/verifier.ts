import type { AuthorityPolicy, IdentityState, VerificationMethod } from "./model.js";
import {
  encodeControllerProofSigningInput,
  encodeOperation,
  encodeOperationSigningInput,
  encodeRecoverySigningInput,
} from "./operation.js";
import type { OpenIdentityOperation } from "./operation.js";
import { StateHash } from "./state-hash.js";
import { encodeIdentityState } from "./state-codec.js";
import type { SignatureProof, SignedOperation } from "./signed-operation.js";
import { verifyEd25519, verifyMlDsa65 } from "./crypto.js";
import { encodeRecoveryPolicy, recoveryCommitment } from "./recovery.js";
import { OpenIdentityValidationError } from "./errors.js";

function verifyMethod(
  method: VerificationMethod,
  input: Uint8Array,
  signature: Uint8Array,
): boolean {
  return method.key.kind === "Ed25519"
    ? verifyEd25519(method.key, input, signature)
    : verifyMlDsa65(method.key, input, signature);
}

function proofMap(
  proofs: readonly SignatureProof[],
  duplicateCode: "DUPLICATE_PROOF" | "DUPLICATE_RECOVERY_PROOF",
): Map<string, SignatureProof> {
  const result = new Map<string, SignatureProof>();
  for (const proof of proofs) {
    const id = proof.methodId.toHex();
    if (result.has(id)) throw new OpenIdentityValidationError(duplicateCode);
    result.set(id, proof);
  }
  return result;
}

function verifyAuthority(
  policy: AuthorityPolicy,
  input: Uint8Array,
  proofs: readonly SignatureProof[],
): void {
  const supplied = proofMap(proofs, "DUPLICATE_PROOF");
  const authorized = new Map(policy.methods.map((method) => [method.id.toHex(), method]));
  let valid = 0;
  for (const [id, proof] of supplied) {
    const method = authorized.get(id);
    if (method === undefined)
      throw new OpenIdentityValidationError("UNAUTHORIZED_VERIFICATION_METHOD");
    if (!verifyMethod(method, input, proof.signature)) {
      throw new OpenIdentityValidationError("INVALID_SIGNATURE");
    }
    valid += 1;
  }
  if (valid < policy.threshold) {
    throw new OpenIdentityValidationError("CONTROLLER_THRESHOLD_NOT_SATISFIED");
  }
}

function verifyPossession(
  policy: AuthorityPolicy,
  operationBytes: Uint8Array,
  proofs: readonly SignatureProof[],
): void {
  const supplied = proofMap(proofs, "DUPLICATE_PROOF");
  for (const method of policy.methods) {
    const proof = supplied.get(method.id.toHex());
    if (proof === undefined) throw new OpenIdentityValidationError("MISSING_PROOF_OF_POSSESSION");
    if (
      !verifyMethod(
        method,
        encodeControllerProofSigningInput(operationBytes, method.id),
        proof.signature,
      )
    ) {
      throw new OpenIdentityValidationError("INVALID_PROOF_OF_POSSESSION");
    }
  }
}

function validateChain(current: IdentityState, operation: OpenIdentityOperation): void {
  if (operation.operationType === 1) return;
  if (operation.sequence !== current.sequence + 1n) {
    throw new OpenIdentityValidationError("INVALID_SEQUENCE");
  }
  const hash = StateHash.fromStateBytes(encodeIdentityState(current));
  if (!hash.equals(operation.previousStateHash)) {
    throw new OpenIdentityValidationError("INVALID_PREVIOUS_STATE_HASH");
  }
}

export function verifyStatefulSignedOperation(
  current: IdentityState,
  signed: SignedOperation,
): void {
  const operation = signed.operation;
  if (operation.operationType === 1) {
    throw new RangeError("CREATE requires bootstrap validation");
  }
  validateChain(current, operation);
  const operationBytes = encodeOperation(operation);

  if (operation.operationType === 3) {
    if (current.recoveryCommitment === undefined) {
      throw new OpenIdentityValidationError("RECOVERY_NOT_CONFIGURED");
    }
    const revealed = recoveryCommitment(encodeRecoveryPolicy(operation.currentRecoveryPolicy));
    if (!revealed.equals(new StateHash(current.recoveryCommitment))) {
      throw new OpenIdentityValidationError("INVALID_RECOVERY_POLICY");
    }
    if (operation.newRecoveryCommitment.equals(revealed)) {
      throw new OpenIdentityValidationError("INVALID_RECOVERY_COMMITMENT");
    }
    verifyPossession(operation.controllerPolicy, operationBytes, signed.controllerProofs ?? []);

    const proofs = proofMap(signed.recoveryProofs ?? [], "DUPLICATE_RECOVERY_PROOF");
    const authorized = new Map(
      operation.currentRecoveryPolicy.methods.map((method) => [method.id.toHex(), method]),
    );
    let valid = 0;
    for (const [id, proof] of proofs) {
      const method = authorized.get(id);
      if (method === undefined) {
        throw new OpenIdentityValidationError("UNAUTHORIZED_RECOVERY_METHOD");
      }
      if (
        !verifyMethod(
          method,
          encodeRecoverySigningInput(operationBytes, method.id),
          proof.signature,
        )
      ) {
        throw new OpenIdentityValidationError("INVALID_RECOVERY_SIGNATURE");
      }
      valid += 1;
    }
    if (valid < operation.currentRecoveryPolicy.threshold) {
      throw new OpenIdentityValidationError("RECOVERY_THRESHOLD_NOT_SATISFIED");
    }
    return;
  }

  verifyAuthority(
    current.controllerPolicy,
    encodeOperationSigningInput(operationBytes),
    signed.authorizationProofs ?? [],
  );

  if (operation.operationType === 2) {
    verifyPossession(operation.controllerPolicy, operationBytes, signed.controllerProofs ?? []);
  } else if (operation.operationType === 5 && operation.assertionPolicy !== null) {
    verifyPossession(operation.assertionPolicy, operationBytes, signed.controllerProofs ?? []);
  }
}
