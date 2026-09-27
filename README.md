# OpenIdentity TypeScript SDK

Production TypeScript SDK for OpenIdentity Protocol — identity lifecycle, cryptographic authority, recovery, credentials, and conformance.

## Status

Early development. This SDK targets the frozen **OpenIdentity Protocol v0.1.1** and is being implemented independently against the normative specifications, CDDL, vectors, and published checksums.

The Java SDK is an interoperability peer, not the normative source for this implementation.

## Requirements

- Node.js 22+
- npm

## Development

```bash
npm install
npm run verify
```

## Initial conformance plan

1. Core byte-safe value types and IdentityId vectors.
2. Deterministic CBOR and StateHash vectors.
3. Verification methods, policies, and Ed25519.
4. Canonical operation encode/decode and state transitions.
5. ML-DSA-65 and hybrid conformance.
6. OI-003 credentials and historical assertion verification.
7. W3C deterministic projections.
8. Resolver client and Java/TypeScript interoperability gate.

## Protocol compatibility

This repository targets **OpenIdentity Protocol v0.1.1**. Released protocol artifacts are consumed as immutable conformance inputs and are not rewritten to make this implementation pass.

## License

Apache License 2.0.
