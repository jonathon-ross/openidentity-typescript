import { encodeBase58Btc } from "./base58btc.js";
import { decodeSecuredCredential, encodeSecuredCredential } from "./credential.js";
import type { ClaimValue, SecuredCredential } from "./credential.js";
import type { IdentityState } from "./model.js";
import { verifyCredentialAgainstHistoricalState } from "./credential-verifier.js";

const BASIC = "https://openidentity.foundation/test/credentials/basic/v1";
const CONTEXTS = [
  "https://www.w3.org/ns/credentials/v2",
  "https://openidentity.foundation/ns/v2",
  BASIC + "/context",
] as const;
const TYPES = [
  "VerifiableCredential",
  "OpenIdentityCredential",
  "OpenIdentityBasicCredential",
] as const;

export interface W3cCredentialProjection {
  readonly "@context": readonly string[];
  readonly id: string;
  readonly type: readonly string[];
  readonly issuer: string;
  readonly validFrom: string;
  readonly validUntil?: string;
  readonly credentialSubject: Readonly<Record<string, unknown>>;
  readonly openIdentityCredentialProfile: string;
  readonly openIdentityIssuanceStateHash: string;
  readonly openIdentitySecuredCredential: string;
  readonly proof?: unknown;
}

export type ProjectionErrorCode =
  | "INVALID_NATIVE_SECURED_CREDENTIAL"
  | "INVALID_PROJECTED_CREDENTIAL_ID"
  | "INVALID_PROJECTED_ISSUER"
  | "INVALID_PROJECTED_VALIDITY"
  | "INVALID_PROJECTED_CREDENTIAL_PROFILE"
  | "INVALID_PROJECTED_ISSUANCE_STATE_HASH"
  | "INVALID_PROJECTED_SUBJECT"
  | "INVALID_PROJECTED_CLAIMS"
  | "UNSUPPORTED_CREDENTIAL_PROFILE"
  | "UNSUPPORTED_PROJECTION_CONTEXT"
  | "MISLEADING_W3C_PROOF"
  | "HISTORICAL_ASSERTION_AUTHORITY_REQUIRED";

export class ProjectionException extends Error {
  constructor(readonly code: ProjectionErrorCode) {
    super(code);
    this.name = "ProjectionException";
  }
}

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}
function time(seconds: bigint): string {
  const millis = seconds * 1000n;
  if (millis > BigInt(Number.MAX_SAFE_INTEGER)) throw new RangeError("Timestamp too large");
  return new Date(Number(millis)).toISOString().replace(".000Z", "Z");
}
function stringClaim(value: ClaimValue | undefined): string {
  if (typeof value !== "string" || value.length === 0)
    throw new ProjectionException("INVALID_PROJECTED_CLAIMS");
  return value;
}
function booleanClaim(value: ClaimValue | undefined): boolean {
  if (typeof value !== "boolean") throw new ProjectionException("INVALID_PROJECTED_CLAIMS");
  return value;
}
function basicSubject(secured: SecuredCredential): Readonly<Record<string, unknown>> {
  const credential = secured.credential;
  if (credential.credentialProfile !== BASIC)
    throw new ProjectionException("UNSUPPORTED_CREDENTIAL_PROFILE");
  if (credential.claims.size !== 3) throw new ProjectionException("INVALID_PROJECTED_CLAIMS");
  const subjectId = "urn:openidentity:test-subject:u" + b64(credential.credentialSubject);
  return {
    id: subjectId,
    name: stringClaim(credential.claims.get("name")),
    role: stringClaim(credential.claims.get("role")),
    active: booleanClaim(credential.claims.get("active")),
  };
}

export function projectW3cCredential(secured: SecuredCredential): W3cCredentialProjection {
  const c = secured.credential;
  const securedBytes = encodeSecuredCredential(secured);
  const base = {
    "@context": CONTEXTS,
    id: "urn:openidentity:credential:u" + b64(c.credentialId),
    type: TYPES,
    issuer: c.issuerIdentity.toDid(),
    validFrom: time(c.validFrom),
    credentialSubject: basicSubject(secured),
    openIdentityCredentialProfile: c.credentialProfile,
    openIdentityIssuanceStateHash: "z" + encodeBase58Btc(c.issuanceStateHash.bytes()),
    openIdentitySecuredCredential: "u" + b64(securedBytes),
  };
  return c.validUntil === undefined ? base : { ...base, validUntil: time(c.validUntil) };
}

function equalJson(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

export function validateW3cCredentialProjection(
  projected: W3cCredentialProjection,
  historical: IdentityState,
): void {
  if (projected.proof !== undefined) throw new ProjectionException("MISLEADING_W3C_PROOF");
  if (!equalJson(projected["@context"], CONTEXTS))
    throw new ProjectionException("UNSUPPORTED_PROJECTION_CONTEXT");
  if (!projected.openIdentitySecuredCredential.startsWith("u")) {
    throw new ProjectionException("INVALID_NATIVE_SECURED_CREDENTIAL");
  }
  let secured: SecuredCredential;
  try {
    secured = decodeSecuredCredential(
      Uint8Array.from(Buffer.from(projected.openIdentitySecuredCredential.slice(1), "base64url")),
    );
    verifyCredentialAgainstHistoricalState(secured, historical);
  } catch {
    throw new ProjectionException("INVALID_NATIVE_SECURED_CREDENTIAL");
  }
  if (
    !secured.credential.issuanceStateHash.equals(
      historical.stateVersion === 1 || historical.stateVersion === 2
        ? secured.credential.issuanceStateHash
        : secured.credential.issuanceStateHash,
    )
  )
    throw new ProjectionException("HISTORICAL_ASSERTION_AUTHORITY_REQUIRED");

  const expected = projectW3cCredential(secured);
  if (projected.id !== expected.id)
    throw new ProjectionException("INVALID_PROJECTED_CREDENTIAL_ID");
  if (projected.issuer !== expected.issuer)
    throw new ProjectionException("INVALID_PROJECTED_ISSUER");
  if (projected.validFrom !== expected.validFrom || projected.validUntil !== expected.validUntil) {
    throw new ProjectionException("INVALID_PROJECTED_VALIDITY");
  }
  if (projected.openIdentityCredentialProfile !== expected.openIdentityCredentialProfile) {
    throw new ProjectionException("INVALID_PROJECTED_CREDENTIAL_PROFILE");
  }
  if (projected.openIdentityIssuanceStateHash !== expected.openIdentityIssuanceStateHash) {
    throw new ProjectionException("INVALID_PROJECTED_ISSUANCE_STATE_HASH");
  }
  const actualSubject = projected.credentialSubject;
  const expectedSubject = expected.credentialSubject;
  if (actualSubject.id !== expectedSubject.id)
    throw new ProjectionException("INVALID_PROJECTED_SUBJECT");
  if (!equalJson(actualSubject, expectedSubject))
    throw new ProjectionException("INVALID_PROJECTED_CLAIMS");
  if (!equalJson(projected.type, expected.type))
    throw new ProjectionException("INVALID_PROJECTED_CLAIMS");
}
