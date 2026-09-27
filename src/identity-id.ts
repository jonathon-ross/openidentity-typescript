import { copyExact, equalBytes, fromHex, hex } from "./bytes.js";

export class IdentityId {
  static readonly LENGTH = 32;
  readonly #bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    this.#bytes = copyExact(bytes, IdentityId.LENGTH, "IdentityId");
  }

  static fromHex(value: string): IdentityId {
    return new IdentityId(fromHex(value));
  }

  bytes(): Uint8Array {
    return this.#bytes.slice();
  }

  toHex(): string {
    return hex(this.#bytes);
  }

  equals(other: IdentityId): boolean {
    return equalBytes(this.#bytes, other.#bytes);
  }
}
