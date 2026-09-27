import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const directory = resolve(root, "protocol", "v0.1.1");

const resources = [
  {
    resource: "identity-id-v0.1.json",
    publishedSha256: "625a795a02f2ffed3fb88c8187937a68f0b97ef5cfe61f76c632f1ef5a2abd92",
  },
  {
    resource: "state-hash-v0.1.json",
    publishedSha256: "6de35a98941f6aff846cd662ccd796473f8f22c5c891ce3589e9a593588bf937",
  },
  {
    resource: "cryptographic-agility-v0.1.json",
    publishedSha256: "4b2cc1d19d9c2c31216ce5db541bc59d1651259162d4edf02eceff46b612b577",
  },
  {
    resource: "assertion-authority-v0.1.json",
    publishedSha256: "39d9f6c6af8aef469ebf7061de95bfb0ae85db21409c58fe901fd93756ec0d0e",
  },
  {
    resource: "recovery-v0.1.json",
    publishedSha256: "a3c4020a5b65b05d8440718bc114bd351c21699a2b6f5f57c67b011cfb87090f",
  },
  {
    resource: "signature-envelope-v0.1.json",
    publishedSha256: "61ea787161c408332354c3bbc04a3538d9cb568524340408b00afe2c391189b5",
  },
  {
    resource: "credential-v0.1.json",
    publishedSha256: "11642669f5588620e55fdefed85b807878d23cf9b607c59ed230d0cd38ad47ae",
  },
  {
    resource: "w3c-credential-projection-v0.1.json",
    publishedSha256: "2730f3cb4b8598cea65ecfa7102de1c95c2e32302fa26b3285f6f58fefb0588e",
  },
];

for (const { resource, publishedSha256 } of resources) {
  const bytes = readFileSync(resolve(directory, resource));
  const candidates = [bytes];

  // Git checkouts may materialize text files with CRLF on Windows. The
  // protocol digest is over the published LF bytes, so verify both the
  // checkout bytes and their LF-normalized representation without
  // modifying the frozen resource.
  const lfNormalized = Buffer.from(bytes.toString("utf8").replaceAll("\r\n", "\n"), "utf8");
  if (!bytes.equals(lfNormalized)) candidates.push(lfNormalized);

  const matched = candidates.some(
    (candidate) => createHash("sha256").update(candidate).digest("hex") === publishedSha256,
  );

  if (!matched) {
    throw new Error(`Protocol resource checksum mismatch: ${resource}`);
  }

  console.log(`PASS ${resource} ${publishedSha256}`);
}
