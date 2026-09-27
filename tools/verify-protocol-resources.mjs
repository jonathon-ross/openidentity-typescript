import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const resources = [
  "identity-id-v0.1.json",
  "state-hash-v0.1.json",
];

for (const name of resources) {
  const directory = resolve(root, "protocol", "v0.1.1");
  const bytes = readFileSync(resolve(directory, name));
  const published = readFileSync(resolve(directory, name + ".sha256"), "utf8").trim();
  const expected = published.split(/\s+/u)[0];
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (actual !== expected) {
    throw new Error(`Protocol resource checksum mismatch: ${basename(name)}`);
  }
  console.log(`PASS ${name} ${actual}`);
}
