# OpenIdentity TypeScript SDK

TypeScript SDK for **OpenIdentity Protocol v0.1.1**: identity lifecycle, deterministic state, controller and recovery authority, OI-003 credentials, historical assertion verification, and deterministic W3C credential projection.

## Status

This SDK targets the frozen **OpenIdentity Protocol v0.1.1** and is implemented independently against its normative specifications, CDDL, conformance vectors, and published checksums.

The Java SDK is an interoperability peer, not the normative source for this implementation.

## Requirements

- **Node.js 24.15.0 or newer**
- npm

Node 24.15+ is required because the SDK uses Node's native Ed25519 and ML-DSA-65 support, including raw ML-DSA public-key import.

## Install

```bash
npm install @openidentity/sdk
```

## Identity identifiers

```ts
import { IdentityId } from "@openidentity/sdk";

const identity = IdentityId.fromDid("did:open:z...");
console.log(identity.toDid());
console.log(identity.toHex());
```

## Decode and verify an OI-003 credential

Native OI-003 verification is bound to the exact historical IdentityState identified by the credential's signed `issuanceStateHash`.

```ts
import {
  decodeIdentityState,
  decodeSecuredCredential,
  verifyCredentialAgainstHistoricalState,
} from "@openidentity/sdk";

const secured = decodeSecuredCredential(securedCredentialBytes);
const historical = decodeIdentityState(historicalStateBytes);

verifyCredentialAgainstHistoricalState(secured, historical);
```

The verifier does **not** substitute the issuer's current state or ControllerPolicy for historical AssertionPolicy authority.

## W3C credential projection

```ts
import {
  projectW3cCredential,
  validateW3cCredentialProjection,
} from "@openidentity/sdk";

const projected = projectW3cCredential(secured);
validateW3cCredentialProjection(projected, historical);
```

The W3C representation is a deterministic projection. Canonical native OI-003 CBOR remains the cryptographic source of truth. Native OI-003 proofs are not represented as W3C `DataIntegrityProof` values.

## Development

```bash
npm install
npm run release:gate
```

The release gate verifies pinned protocol-resource checksums, formatting, lint, TypeScript types, the complete conformance/security test suite, declaration/build output, and the packed npm consumer surface.

## Protocol compatibility

This repository targets **OpenIdentity Protocol v0.1.1**. Released protocol artifacts are consumed as immutable conformance inputs and are not rewritten to make this implementation pass.

The SDK supports:

- deterministic CBOR and StateHash processing;
- CREATE, ROTATE_CONTROLLER, RECOVER, DEACTIVATE, and SET_ASSERTION_POLICY;
- Ed25519 and ML-DSA-65;
- SINGLE and hybrid threshold policies;
- controller, proof-of-possession, and recovery authorization;
- OI-003 native credentials and historical AssertionPolicy verification; and
- deterministic W3C VC projection with projection-consistency validation.

## License

Apache License 2.0.
