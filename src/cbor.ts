export type CborValue =
  bigint | Uint8Array | string | null | readonly CborValue[] | ReadonlyMap<CborValue, CborValue>;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function head(major: number, value: bigint): Uint8Array {
  if (value < 0n) throw new RangeError("CBOR argument must be non-negative");
  if (value < 24n) return Uint8Array.of((major << 5) | Number(value));
  if (value <= 0xffn) return Uint8Array.of((major << 5) | 24, Number(value));
  if (value <= 0xffffn) {
    return Uint8Array.of((major << 5) | 25, Number(value >> 8n), Number(value & 0xffn));
  }
  if (value <= 0xffffffffn) {
    const out = new Uint8Array(5);
    out[0] = (major << 5) | 26;
    new DataView(out.buffer).setUint32(1, Number(value), false);
    return out;
  }
  if (value <= 0xffffffffffffffffn) {
    const out = new Uint8Array(9);
    out[0] = (major << 5) | 27;
    new DataView(out.buffer).setBigUint64(1, value, false);
    return out;
  }
  throw new RangeError("CBOR integer exceeds uint64");
}

function compareKeys(left: Uint8Array, right: Uint8Array): number {
  if (left.length !== right.length) return left.length - right.length;
  for (let index = 0; index < left.length; index += 1) {
    const a = left.at(index);
    const b = right.at(index);
    if (a === undefined || b === undefined) throw new Error("Unexpected key bounds");
    if (a !== b) return a - b;
  }
  return 0;
}

export function encodeDeterministic(value: CborValue): Uint8Array {
  if (typeof value === "bigint") {
    return value >= 0n ? head(0, value) : head(1, -1n - value);
  }
  if (value === null) return Uint8Array.of(0xf6);
  if (value instanceof Uint8Array) return concat([head(2, BigInt(value.length)), value]);
  if (typeof value === "string") {
    const bytes = textEncoder.encode(value);
    return concat([head(3, BigInt(bytes.length)), bytes]);
  }
  if (Array.isArray(value)) {
    const items: readonly CborValue[] = value;
    return concat([head(4, BigInt(items.length)), ...items.map(encodeDeterministic)]);
  }
  if (value instanceof Map) {
    const map: ReadonlyMap<CborValue, CborValue> = value;
    const entries = [...map.entries()].map(([key, item]) => {
      const encodedKey = encodeDeterministic(key);
      return { encodedKey, encodedValue: encodeDeterministic(item) };
    });
    entries.sort((a, b) => compareKeys(a.encodedKey, b.encodedKey));
    for (let index = 1; index < entries.length; index += 1) {
      const previous = entries.at(index - 1);
      const current = entries.at(index);
      if (previous === undefined || current === undefined) {
        throw new Error("Unexpected CBOR map-entry bounds");
      }
      if (compareKeys(previous.encodedKey, current.encodedKey) === 0) {
        throw new RangeError("Duplicate CBOR map key");
      }
    }
    return concat([
      head(5, BigInt(entries.length)),
      ...entries.flatMap((entry) => [entry.encodedKey, entry.encodedValue]),
    ]);
  }
  throw new TypeError("Unsupported CBOR value");
}

class Reader {
  #offset = 0;
  constructor(private readonly bytes: Uint8Array) {}

  read(): CborValue {
    const initial = this.byte();
    const major = initial >> 5;
    const additional = initial & 0x1f;
    if (additional === 31) throw new RangeError("Indefinite-length CBOR is prohibited");
    if (major === 7) {
      if (initial === 0xf6) return null;
      throw new RangeError("Unsupported CBOR simple/float value");
    }
    const argument = this.argument(additional);
    if (major === 0) return argument;
    if (major === 1) return -1n - argument;
    const length = this.safeLength(argument);
    if (major === 2) return this.take(length);
    if (major === 3) return textDecoder.decode(this.take(length));
    if (major === 4) return Array.from({ length }, () => this.read());
    if (major === 5) {
      const map = new Map<CborValue, CborValue>();
      const seen = new Set<string>();
      let previousKey: Uint8Array | undefined;
      for (let index = 0; index < length; index += 1) {
        const keyStart = this.#offset;
        const key = this.read();
        const keyBytes = this.bytes.slice(keyStart, this.#offset);
        const fingerprint = Buffer.from(keyBytes).toString("hex");
        if (seen.has(fingerprint)) throw new RangeError("Duplicate CBOR map key");
        seen.add(fingerprint);
        if (previousKey !== undefined && compareKeys(previousKey, keyBytes) >= 0) {
          throw new RangeError("Non-deterministic CBOR map-key ordering");
        }
        previousKey = keyBytes;
        map.set(key, this.read());
      }
      return map;
    }
    throw new RangeError("CBOR tags are prohibited");
  }

  done(): boolean {
    return this.#offset === this.bytes.length;
  }

  byte(): number {
    const value = this.bytes.at(this.#offset);
    if (value === undefined) throw new RangeError("Truncated CBOR");
    this.#offset += 1;
    return value;
  }

  take(length: number): Uint8Array {
    if (this.#offset + length > this.bytes.length) throw new RangeError("Truncated CBOR");
    const value = this.bytes.slice(this.#offset, this.#offset + length);
    this.#offset += length;
    return value;
  }

  safeLength(value: bigint): number {
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new RangeError("CBOR length too large");
    return Number(value);
  }

  argument(additional: number): bigint {
    if (additional < 24) return BigInt(additional);
    const widths = new Map([
      [24, 1],
      [25, 2],
      [26, 4],
      [27, 8],
    ]);
    const width = widths.get(additional);
    if (width === undefined) throw new RangeError("Reserved CBOR additional information");
    const bytes = this.take(width);
    let value = 0n;
    for (const byte of bytes) value = (value << 8n) | BigInt(byte);
    const minimum = width === 1 ? 24n : 1n << BigInt((width / 2) * 8);
    if (value < minimum) throw new RangeError("Non-preferred CBOR integer/length encoding");
    return value;
  }
}

export function decodeDeterministic(bytes: Uint8Array): CborValue {
  const reader = new Reader(bytes);
  const value = reader.read();
  if (!reader.done()) throw new RangeError("Trailing bytes after CBOR value");
  return value;
}
