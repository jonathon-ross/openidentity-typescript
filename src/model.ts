import { IdentityId } from "./identity-id.js";
import { VerificationMethodId } from "./verification-method-id.js";

function copy(bytes: Uint8Array): Uint8Array {
  return bytes.slice();
}

export type CoseKey = Ed25519Key | MlDsa65Key;

export class Ed25519Key {
  readonly kind = "Ed25519";
  readonly #publicKey: Uint8Array;

  constructor(publicKey: Uint8Array) {
    if (publicKey.length !== 32) throw new RangeError("Ed25519 public key must be 32 bytes");
    this.#publicKey = copy(publicKey);
  }

  publicKey(): Uint8Array {
    return copy(this.#publicKey);
  }
}

export class MlDsa65Key {
  readonly kind = "ML-DSA-65";
  readonly #publicKey: Uint8Array;

  constructor(publicKey: Uint8Array) {
    if (publicKey.length !== 1952) throw new RangeError("ML-DSA-65 public key must be 1952 bytes");
    this.#publicKey = copy(publicKey);
  }

  publicKey(): Uint8Array {
    return copy(this.#publicKey);
  }
}

export interface VerificationMethod {
  readonly id: VerificationMethodId;
  readonly key: CoseKey;
}

export interface AuthorityPolicy {
  readonly threshold: number;
  readonly methods: readonly VerificationMethod[];
}

export interface IdentityStateV1 {
  readonly stateVersion: 1;
  readonly identity: IdentityId;
  readonly sequence: bigint;
  readonly status: bigint;
  readonly controllerPolicy: AuthorityPolicy;
  readonly recoveryCommitment?: Uint8Array;
}

export interface IdentityStateV2 {
  readonly stateVersion: 2;
  readonly identity: IdentityId;
  readonly sequence: bigint;
  readonly status: bigint;
  readonly controllerPolicy: AuthorityPolicy;
  readonly recoveryCommitment?: Uint8Array;
  readonly assertionPolicy?: AuthorityPolicy;
}

export type IdentityState = IdentityStateV1 | IdentityStateV2;
