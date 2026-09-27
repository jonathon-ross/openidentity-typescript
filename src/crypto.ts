import { createPublicKey, verify } from "node:crypto";
import type { Ed25519Key, MlDsa65Key } from "./model.js";

const ED25519_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  const result = new Uint8Array(left.length + right.length);
  result.set(left);
  result.set(right, left.length);
  return result;
}

export function verifyEd25519(
  key: Ed25519Key,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (signature.length !== 64) return false;
  const publicKey = createPublicKey({
    key: Buffer.from(concat(ED25519_SPKI_PREFIX, key.publicKey())),
    format: "der",
    type: "spki",
  });
  return verify(null, Buffer.from(message), publicKey, Buffer.from(signature));
}

export function verifyMlDsa65(
  key: MlDsa65Key,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (signature.length !== 3309) return false;
  const publicKey = createPublicKey({
    key: Buffer.from(key.publicKey()),
    format: "raw-public",
    asymmetricKeyType: "ml-dsa-65",
  });
  return verify(null, Buffer.from(message), publicKey, Buffer.from(signature));
}
