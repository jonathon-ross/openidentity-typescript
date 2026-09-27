import type { IdentityState, IdentityStateV2 } from "./model.js";
import { StateHash } from "./state-hash.js";
import { encodeIdentityState } from "./state-codec.js";
import type {
  DeactivateOperation,
  RecoverOperation,
  SetAssertionPolicyOperation,
} from "./operation.js";
import { encodeRecoveryPolicy, recoveryCommitment } from "./recovery.js";

export function applySetAssertionPolicy(
  current: IdentityState,
  operation: SetAssertionPolicyOperation,
): IdentityStateV2 {
  if (!current.identity.equals(operation.identity)) throw new RangeError("INVALID_IDENTITY");
  if (operation.sequence !== current.sequence + 1n) throw new RangeError("INVALID_SEQUENCE");

  const common = {
    stateVersion: 2 as const,
    identity: current.identity,
    sequence: operation.sequence,
    status: current.status,
    controllerPolicy: current.controllerPolicy,
    ...(current.recoveryCommitment === undefined
      ? {}
      : { recoveryCommitment: current.recoveryCommitment }),
  };

  return operation.assertionPolicy === null
    ? common
    : { ...common, assertionPolicy: operation.assertionPolicy };
}

export function applyDeactivate(
  current: IdentityState,
  operation: DeactivateOperation,
): IdentityState {
  if (current.status !== 1n) throw new RangeError("IDENTITY_DEACTIVATED");
  if (!current.identity.equals(operation.identity)) throw new RangeError("INVALID_IDENTITY");
  if (operation.sequence !== current.sequence + 1n) throw new RangeError("INVALID_SEQUENCE");
  const currentHash = StateHash.fromStateBytes(encodeIdentityState(current));
  if (!currentHash.equals(operation.previousStateHash)) {
    throw new RangeError("INVALID_PREVIOUS_STATE_HASH");
  }

  const common = {
    identity: current.identity,
    sequence: operation.sequence,
    status: 2n,
    controllerPolicy: current.controllerPolicy,
    ...(current.recoveryCommitment === undefined
      ? {}
      : { recoveryCommitment: current.recoveryCommitment }),
  };

  if (current.stateVersion === 1) {
    return { stateVersion: 1, ...common };
  }
  return {
    stateVersion: 2,
    ...common,
    ...(current.assertionPolicy === undefined ? {} : { assertionPolicy: current.assertionPolicy }),
  };
}

export function applyRecover(current: IdentityState, operation: RecoverOperation): IdentityState {
  if (!current.identity.equals(operation.identity)) throw new RangeError("INVALID_IDENTITY");
  if (operation.sequence !== current.sequence + 1n) throw new RangeError("INVALID_SEQUENCE");
  const currentHash = StateHash.fromStateBytes(encodeIdentityState(current));
  if (!currentHash.equals(operation.previousStateHash)) {
    throw new RangeError("INVALID_PREVIOUS_STATE_HASH");
  }
  if (current.recoveryCommitment === undefined) throw new RangeError("RECOVERY_NOT_CONFIGURED");
  const revealedCommitment = recoveryCommitment(
    encodeRecoveryPolicy(operation.currentRecoveryPolicy),
  );
  if (!revealedCommitment.equals(new StateHash(current.recoveryCommitment))) {
    throw new RangeError("INVALID_RECOVERY_POLICY");
  }
  if (operation.newRecoveryCommitment.equals(revealedCommitment)) {
    throw new RangeError("INVALID_RECOVERY_COMMITMENT");
  }

  const common = {
    identity: current.identity,
    sequence: operation.sequence,
    status: 1n,
    controllerPolicy: operation.controllerPolicy,
    recoveryCommitment: operation.newRecoveryCommitment.bytes(),
  };

  if (current.stateVersion === 1) return { stateVersion: 1, ...common };
  return {
    stateVersion: 2,
    ...common,
    ...(current.assertionPolicy === undefined ? {} : { assertionPolicy: current.assertionPolicy }),
  };
}
