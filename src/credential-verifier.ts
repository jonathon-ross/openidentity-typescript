import type { IdentityState } from "./model.js";
import { encodeIdentityState } from "./state-codec.js";
import { StateHash } from "./state-hash.js";
import type { SecuredCredential } from "./credential.js";
import { encodeCredential, encodeCredentialSigningInput } from "./credential.js";
import { verifyEd25519, verifyMlDsa65 } from "./crypto.js";

export type CredentialVerificationError =
  | "INVALID_ISSUANCE_STATE_HASH"
  | "NO_ASSERTION_AUTHORITY"
  | "DUPLICATE_CREDENTIAL_PROOF"
  | "UNAUTHORIZED_CREDENTIAL_PROOF"
  | "INVALID_CREDENTIAL_SIGNATURE"
  | "ASSERTION_THRESHOLD_NOT_SATISFIED";

export class CredentialVerificationException extends Error {
  constructor(readonly code: CredentialVerificationError) {
    super(code);
    this.name = "CredentialVerificationException";
  }
}

export function verifyCredentialAgainstHistoricalState(
  secured: SecuredCredential,
  historical: IdentityState,
): void {
  const credential = secured.credential;
  const actualHash = StateHash.fromStateBytes(encodeIdentityState(historical));
  if (!actualHash.equals(credential.issuanceStateHash)) {
    throw new CredentialVerificationException("INVALID_ISSUANCE_STATE_HASH");
  }
  if (!historical.identity.equals(credential.issuerIdentity)) {
    throw new CredentialVerificationException("INVALID_ISSUANCE_STATE_HASH");
  }
  if (historical.stateVersion !== 2 || historical.assertionPolicy === undefined) {
    throw new CredentialVerificationException("NO_ASSERTION_AUTHORITY");
  }

  const credentialBytes = encodeCredential(credential);
  const input = encodeCredentialSigningInput(credentialBytes);
  const authorized = new Map(
    historical.assertionPolicy.methods.map((method) => [method.id.toHex(), method]),
  );
  const seen = new Set<string>();
  let valid = 0;
  for (const proof of secured.proofs) {
    const id = proof.methodId.toHex();
    if (seen.has(id)) throw new CredentialVerificationException("DUPLICATE_CREDENTIAL_PROOF");
    seen.add(id);
    const method = authorized.get(id);
    if (method === undefined) throw new CredentialVerificationException("UNAUTHORIZED_CREDENTIAL_PROOF");
    const ok = method.key.kind === "Ed25519"
      ? verifyEd25519(method.key, input, proof.signature)
      : verifyMlDsa65(method.key, input, proof.signature);
    if (!ok) throw new CredentialVerificationException("INVALID_CREDENTIAL_SIGNATURE");
    valid += 1;
  }
  if (valid < historical.assertionPolicy.threshold) {
    throw new CredentialVerificationException("ASSERTION_THRESHOLD_NOT_SATISFIED");
  }
}
