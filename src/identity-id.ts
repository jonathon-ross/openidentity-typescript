import { copyExact, equalBytes, fromHex, hex } from "./bytes.js";
import { decodeBase58Btc, encodeBase58Btc, isBase58Btc } from "./base58btc.js";

export type IdentityIdErrorCode =
  | "INVALID_DID_SCHEME"
  | "INVALID_DID_METHOD"
  | "INVALID_DID_PREFIX"
  | "MISSING_METHOD_ID"
  | "INVALID_MULTIBASE_PREFIX"
  | "UNSUPPORTED_MULTIBASE"
  | "INVALID_BASE58BTC_CHARACTER"
  | "INVALID_IDENTIFIER_LENGTH"
  | "INVALID_METHOD_ID"
  | "NON_CANONICAL_IDENTIFIER";

export class IdentityIdError extends Error {
  constructor(readonly code: IdentityIdErrorCode) {
    super(code);
    this.name = "IdentityIdError";
  }
}

export class IdentityId {
  static readonly LENGTH = 32;
  readonly #bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    this.#bytes = copyExact(bytes, IdentityId.LENGTH, "IdentityId");
  }

  static fromHex(value: string): IdentityId {
    return new IdentityId(fromHex(value));
  }

  static fromDid(candidate: string): IdentityId {
    if (candidate.startsWith("DID:") || candidate.startsWith("Did:") || candidate.startsWith("dID:")) {
      throw new IdentityIdError("INVALID_DID_PREFIX");
    }
    if (!candidate.startsWith("did:")) throw new IdentityIdError("INVALID_DID_SCHEME");
    if (!candidate.startsWith("did:open:")) {
      if (candidate.startsWith("did:") && !candidate.startsWith("did:open")) {
        throw new IdentityIdError("INVALID_DID_METHOD");
      }
      throw new IdentityIdError("INVALID_DID_PREFIX");
    }

    const methodId = candidate.slice("did:open:".length);
    if (methodId.length === 0) throw new IdentityIdError("MISSING_METHOD_ID");
    if (methodId.includes(":")) throw new IdentityIdError("INVALID_METHOD_ID");

    const prefix = methodId.charAt(0);
    if (prefix !== "z") {
      if (prefix === "u") throw new IdentityIdError("UNSUPPORTED_MULTIBASE");
      throw new IdentityIdError("INVALID_MULTIBASE_PREFIX");
    }

    const payload = methodId.slice(1);
    if (payload.length === 0) throw new IdentityIdError("INVALID_IDENTIFIER_LENGTH");
    if (!isBase58Btc(payload)) throw new IdentityIdError("INVALID_BASE58BTC_CHARACTER");

    const decoded = decodeBase58Btc(payload);
    if (decoded.length !== IdentityId.LENGTH) {
      throw new IdentityIdError("INVALID_IDENTIFIER_LENGTH");
    }
    if (encodeBase58Btc(decoded) !== payload) {
      throw new IdentityIdError("NON_CANONICAL_IDENTIFIER");
    }
    return new IdentityId(decoded);
  }

  bytes(): Uint8Array {
    return this.#bytes.slice();
  }

  toHex(): string {
    return hex(this.#bytes);
  }

  toDid(): string {
    return "did:open:z" + encodeBase58Btc(this.#bytes);
  }

  equals(other: IdentityId): boolean {
    return equalBytes(this.#bytes, other.#bytes);
  }
}
