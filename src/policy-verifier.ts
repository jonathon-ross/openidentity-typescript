import type { AuthorityPolicy, CoseKey, VerificationMethod } from "./model.js";
import type { RecoveryPolicy } from "./recovery.js";
import type { SignatureProof } from "./signed-operation.js";
import { verifyEd25519, verifyMlDsa65 } from "./crypto.js";

function verifyKey(key: CoseKey, message: Uint8Array, signature: Uint8Array): boolean {
  return key.kind === "Ed25519"
    ? verifyEd25519(key, message, signature)
    : verifyMlDsa65(key, message, signature);
}

function verifyThreshold(
  threshold: number,
  methods: readonly VerificationMethod[],
  message: Uint8Array,
  proofs: readonly SignatureProof[],
): boolean {
  const authorized = new Map(methods.map((method) => [method.id.toHex(), method]));
  const seen = new Set<string>();
  let valid = 0;
  for (const proof of proofs) {
    const id = proof.methodId.toHex();
    if (seen.has(id)) return false;
    seen.add(id);
    const method = authorized.get(id);
    if (method === undefined) return false;
    if (verifyKey(method.key, message, proof.signature)) valid += 1;
  }
  return valid >= threshold;
}

export function verifyAuthorityPolicy(
  policy: AuthorityPolicy,
  message: Uint8Array,
  proofs: readonly SignatureProof[],
): boolean {
  return verifyThreshold(policy.threshold, policy.methods, message, proofs);
}

export function verifyRecoveryPolicy(
  policy: RecoveryPolicy,
  messageForMethod: (method: VerificationMethod) => Uint8Array,
  proofs: readonly SignatureProof[],
): boolean {
  const authorized = new Map(policy.methods.map((method) => [method.id.toHex(), method]));
  const seen = new Set<string>();
  let valid = 0;
  for (const proof of proofs) {
    const id = proof.methodId.toHex();
    if (seen.has(id)) return false;
    seen.add(id);
    const method = authorized.get(id);
    if (method === undefined) return false;
    if (verifyKey(method.key, messageForMethod(method), proof.signature)) valid += 1;
  }
  return valid >= policy.threshold;
}
