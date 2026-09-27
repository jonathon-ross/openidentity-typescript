export { IdentityId, IdentityIdError } from "./identity-id.js";
export type { IdentityIdErrorCode } from "./identity-id.js";
export { VerificationMethodId } from "./verification-method-id.js";
export { StateHash } from "./state-hash.js";
export { decodeIdentityState, encodeIdentityState } from "./state-codec.js";
export { Ed25519Key, MlDsa65Key } from "./model.js";
export type {
  AuthorityPolicy,
  CoseKey,
  IdentityState,
  IdentityStateV1,
  IdentityStateV2,
  VerificationMethod,
} from "./model.js";
export {
  decodeCreateOperation,
  encodeCreateOperation,
  encodeOperationSigningInput,
} from "./operation.js";
export type { CreateOperation } from "./operation.js";
export {
  decodeOperation,
  decodeRotateControllerOperation,
  encodeControllerProofSigningInput,
  encodeOperation,
  encodeRotateControllerOperation,
} from "./operation.js";
export type { OpenIdentityOperation, RotateControllerOperation } from "./operation.js";
export {
  decodeSetAssertionPolicyOperation,
  encodeSetAssertionPolicyOperation,
} from "./operation.js";
export type { SetAssertionPolicyOperation } from "./operation.js";
export { applySetAssertionPolicy } from "./transitions.js";
export { decodeDeactivateOperation, encodeDeactivateOperation } from "./operation.js";
export type { DeactivateOperation } from "./operation.js";
export { applyDeactivate } from "./transitions.js";
export {
  decodeRecoverOperation,
  encodeRecoverOperation,
  encodeRecoverySigningInput,
} from "./operation.js";
export type { RecoverOperation } from "./operation.js";
export {
  decodeRecoveryPolicy,
  encodeRecoveryPolicy,
  recoveryCommitment,
} from "./recovery.js";
export type { RecoveryPolicy } from "./recovery.js";
export { applyRecover } from "./transitions.js";
