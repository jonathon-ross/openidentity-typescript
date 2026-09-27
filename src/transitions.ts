import type { IdentityState, IdentityStateV2 } from "./model.js";
import type { SetAssertionPolicyOperation } from "./operation.js";

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
