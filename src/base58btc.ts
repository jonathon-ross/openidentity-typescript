const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const INDEX = new Map([...ALPHABET].map((character, index) => [character, index]));

export function encodeBase58Btc(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros += 1;

  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);

  let encoded = "";
  while (value > 0n) {
    const remainder = Number(value % 58n);
    encoded = ALPHABET.charAt(remainder) + encoded;
    value /= 58n;
  }
  return "1".repeat(zeros) + encoded;
}

export function decodeBase58Btc(value: string): Uint8Array {
  let zeros = 0;
  while (zeros < value.length && value.charAt(zeros) === "1") zeros += 1;

  let number = 0n;
  for (const character of value) {
    const digit = INDEX.get(character);
    if (digit === undefined) throw new RangeError("INVALID_BASE58BTC_CHARACTER");
    number = number * 58n + BigInt(digit);
  }

  const body: number[] = [];
  while (number > 0n) {
    body.push(Number(number & 0xffn));
    number >>= 8n;
  }
  body.reverse();
  return Uint8Array.from([...new Array<number>(zeros).fill(0), ...body]);
}

export function isBase58Btc(value: string): boolean {
  return [...value].every((character) => INDEX.has(character));
}
