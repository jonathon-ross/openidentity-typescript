import { createHash } from "node:crypto";
import { copyExact, equalBytes, fromHex, hex } from "./bytes.js";

export class StateHash {
  static readonly LENGTH = 34;
  static readonly SHA2_256_CODE = 0x12;
  static readonly SHA2_256_LENGTH = 0x20;
  readonly #bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    const copy = copyExact(bytes, StateHash.LENGTH, "StateHash");
    if (copy[0] !== StateHash.SHA2_256_CODE || copy[1] !== StateHash.SHA2_256_LENGTH) {
      throw new RangeError("StateHash must be a SHA2-256 Multihash");
    }
    this.#bytes = copy;
  }

  static fromStateBytes(stateBytes: Uint8Array): StateHash {
    const digest = createHash("sha256").update(stateBytes).digest();
    return new StateHash(Uint8Array.of(0x12, 0x20, ...digest));
  }

  static fromHex(value: string): StateHash {
    return new StateHash(fromHex(value));
  }

  bytes(): Uint8Array {
    return this.#bytes.slice();
  }

  toHex(): string {
    return hex(this.#bytes);
  }

  equals(other: StateHash): boolean {
    return equalBytes(this.#bytes, other.#bytes);
  }
}
