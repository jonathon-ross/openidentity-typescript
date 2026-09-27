import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(".");
const work = mkdtempSync(join(tmpdir(), "openidentity-sdk-smoke-"));
const npmCli = process.env.npm_execpath;
if (npmCli === undefined || npmCli.length === 0) {
  throw new Error("package:smoke must be run through npm so npm_execpath is available");
}
let tarball;

function npm(args, options = {}) {
  return execFileSync(process.execPath, [npmCli, ...args], options);
}

try {
  const packJson = npm(["pack", "--json", "--ignore-scripts"], {
    cwd: root,
    encoding: "utf8",
  });
  const packed = JSON.parse(packJson);
  const filename = packed[0]?.filename;
  if (typeof filename !== "string") throw new Error("npm pack did not return a tarball filename");

  tarball = join(root, filename);
  writeFileSync(
    join(work, "package.json"),
    JSON.stringify({ type: "module", private: true }, null, 2) + "\n",
  );
  npm(["install", "--ignore-scripts", tarball], {
    cwd: work,
    stdio: "inherit",
  });

  writeFileSync(
    join(work, "smoke.mjs"),
    `import {
  IdentityId,
  StateHash,
  encodeCredentialSigningInput,
} from "@openidentity/sdk";

const id = new IdentityId(Uint8Array.from({ length: 32 }, (_, i) => i));
if (!IdentityId.fromDid(id.toDid()).equals(id)) throw new Error("IdentityId package round-trip failed");

const stateBytes = Uint8Array.of(0xa0);
const hash = StateHash.fromStateBytes(stateBytes);
if (hash.bytes().length !== 34) throw new Error("StateHash package surface failed");

const input = encodeCredentialSigningInput(Uint8Array.of(0xa0));
if (input.length === 0) throw new Error("Credential signing-input package surface failed");
`,
  );

  execFileSync(process.execPath, ["smoke.mjs"], { cwd: work, stdio: "inherit" });

  const metadata = packed[0];
  const files = Array.isArray(metadata?.files) ? metadata.files.map((item) => item.path) : [];
  for (const required of [
    "package.json",
    "README.md",
    "LICENSE",
    "dist/index.js",
    "dist/index.d.ts",
  ]) {
    if (!files.includes(required)) throw new Error("Packed npm artifact missing " + required);
  }

  console.log("PACKED NPM CONSUMER SMOKE: PASS");
} finally {
  if (tarball !== undefined) rmSync(tarball, { force: true });
  rmSync(work, { recursive: true, force: true });
}
