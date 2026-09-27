import { copyExact, equalBytes, fromHex, hex } from "./bytes.js";

export class VerificationMethodId {
  static readonly LENGTH = 16;
  readonly #bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    this.#bytes = copyExact(bytes, VerificationMethodId.LENGTH, "VerificationMethodId");
  }

  static fromHex(value: string): VerificationMethodId {
    return new VerificationMethodId(fromHex(value));
  }

  bytes(): Uint8Array {
    return this.#bytes.slice();
  }

  toHex(): string {
    return hex(this.#bytes);
  }

  equals(other: VerificationMethodId): boolean {
    return equalBytes(this.#bytes, other.#bytes);
  }
}
