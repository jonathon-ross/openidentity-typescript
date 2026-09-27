import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const directory = resolve(root, "protocol", "v0.1.1");

const resources = [
  {
    resource: "identity-id-v0.1.json",
    checksum: "identity-id-v0.1.sha256",
  },
  {
    resource: "state-hash-v0.1.json",
    checksum: "state-hash-v0.1.json.sha256",
  },
];

for (const { resource, checksum } of resources) {
  const bytes = readFileSync(resolve(directory, resource));
  const published = readFileSync(resolve(directory, checksum), "utf8").trim();
  const expected = published.split(/\s+/u)[0];
  const actual = createHash("sha256").update(bytes).digest("hex");

  if (actual !== expected) {
    throw new Error(`Protocol resource checksum mismatch: ${resource}`);
  }

  console.log(`PASS ${resource} ${actual}`);
}
