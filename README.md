# frost-babyjubjub

> [!WARNING]
> This library is **unaudited**. It has not undergone independent security review. Use at your own risk, and do not rely on it for production systems handling real value without a thorough audit.

FROST (Flexible Round-Optimized Schnorr Threshold signatures) and DKG (Distributed Key Generation) over the BabyJubJub curve.

The signing convention and Poseidon-based challenge are deliberately tweaked to be ZK-friendly: signatures produced by this library verify directly inside a [circom](https://docs.circom.io/) circuit (see [`circuits/schnorr_verify.circom`](./circuits/schnorr_verify.circom)), at a fraction of the constraint cost of a generic hash-based challenge. The DKG and FROST math are built on top of [`@noble/curves`](https://github.com/paulmillr/noble-curves).

## Dependencies

- [`@noble/curves`](https://github.com/paulmillr/noble-curves) — BabyJubJub curve arithmetic and the generic FROST/DKG protocol implementation
- [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) — SHA-512 (used internally by the FROST ciphersuite)
- [`circomlib`](https://github.com/iden3/circomlib) — circuit dependency for `schnorr_verify.circom` (Poseidon, BabyJubJub point ops, bit decomposition)

## Quick Start

### 1. Distributed Key Generation (DKG)

A threshold setup requires $t$-of-$n$ participants (e.g. 2-of-3). The DKG runs in 3 rounds.

```typescript
import { dkgRound1, dkgRound2, dkgRound3 } from "frost-babyjubjub";

const threshold = 2;
const total = 3;

// Round 1 (each participant)
const aliceR1 = dkgRound1({ address: "alice", threshold, total });
const bobR1 = dkgRound1({ address: "bob", threshold, total });
const carolR1 = dkgRound1({ address: "carol", threshold, total });

// Broadcast each participant's round1.public to everyone else...

// Round 2 (each participant, given the others' round-1 public broadcasts)
const aliceR2 = dkgRound2({
  myRound1Secret: aliceR1.secret,
  othersRound1Public: [bobR1.public, carolR1.public],
});
// (Bob and Carol do the same...)

// Send each recipient their entry from the round2 map, then:

// Round 3 (finalize the key)
const aliceKey = dkgRound3({
  myRound1Secret: aliceR1.secret,
  othersRound1Public: [bobR1.public, carolR1.public],
  othersRound2Public: [
    bobR2[aliceR1.public.identifier],
    carolR2[aliceR1.public.identifier],
  ],
});

// aliceKey.public.commitments[0] is the group public key.
// aliceKey.secret is alice's signing share.
```

### 2. Threshold Signing

Signing requires $t$ participants to interact in 2 rounds.

```typescript
import {
  frostCommit,
  frostSign,
  frostAggregate,
  poseidon,
} from "frost-babyjubjub";

const msg = poseidon([123n, 456n]); // the message to sign, as a field element

// Round 1: commitments
const aliceCommit = frostCommit(aliceKey.secret);
const bobCommit = frostCommit(bobKey.secret);
const commitmentList = [aliceCommit.commitments, bobCommit.commitments];

// Round 2: signature shares
const aliceShare = frostSign(
  aliceKey.secret,
  aliceKey.public,
  aliceCommit.nonces,
  commitmentList,
  msg,
);
const bobShare = frostSign(
  bobKey.secret,
  bobKey.public,
  bobCommit.nonces,
  commitmentList,
  msg,
);

// Aggregation (can be done by anyone with the public shares)
const groupSignature = frostAggregate(aliceKey.public, commitmentList, msg, [
  aliceShare,
  bobShare,
]);
```

### 3. Verification

```typescript
import { schnorrVerify } from "frost-babyjubjub";

const isValid = schnorrVerify({
  signature: groupSignature,
  pubkey: groupPubkey,
  message: msg,
});
console.log(isValid); // true
```

The same `(s, e)` signature also verifies inside [`schnorr_verify.circom`](./circuits/schnorr_verify.circom) — see [`test/circuit-schnorr.test.ts`](./test/circuit-schnorr.test.ts) for a worked example of computing a witness against it.

### `babyjubjub_FROST`

`babyjubjub_FROST` (from `frost-babyjubjub`) is the raw `@noble/curves` FROST instance for this ciphersuite, exposed mainly because the DKG round functions are thin wrappers around it. **Prefer the dedicated functions** (`dkgRound1`/`dkgRound2`/`dkgRound3`, `frostCommit`/`frostSign`/`frostAggregate`/`frostVerifyShare`) over calling `babyjubjub_FROST` directly — they pin the conventions (identifier derivation, circuit-compatible challenge, etc.) that make this library's output usable in a circuit. Its API otherwise follows `@noble/curves`' generic FROST shape; see the [noble-curves FROST docs](https://github.com/paulmillr/noble-curves#frost-threshold-signatures) for the full reference.

## API Reference

### DKG (`./src/dkg.ts`)

- `dkgRound1({ address, threshold, total })`: generates this participant's polynomial, commitment, and proof of knowledge.
- `dkgRound2({ myRound1Secret, othersRound1Public })`: produces per-recipient signing-share packages from the round-1 broadcasts.
- `dkgRound3({ myRound1Secret, othersRound1Public, othersRound2Public })`: finalizes the group public key and this participant's signing share.

### FROST Signing (`./src/signature.ts`)

Circuit-compatible signing layer — uses the DKG key shares above, but signs/verifies with the `s = k + e·sk`, `R = s·G − e·PK` equation (rather than RFC 9591's literal form) so the result matches `schnorr_verify.circom`.

- `frostCommit(secret)`: generates hiding/binding nonces and their commitments.
- `frostSign(secret, pub, nonces, commitmentList, msg)`: generates a signature share.
- `frostVerifyShare(pub, commitmentList, msg, identifier, sigShare)`: verifies a single participant's signature share.
- `frostAggregate(pub, commitmentList, msg, shares)`: aggregates signature shares into a final `(s, e)` Schnorr signature.

### Schnorr (`./src/schnorr.ts`)

Single-key counterpart to the FROST signing layer above — same `s = k + e·sk` / `R = s·G − e·PK` convention, same circuit compatibility, no DKG/threshold involved.

- `schnorrSign({ message, secretKey })`: produces a `{ s, e }` signature.
- `schnorrVerify({ message, signature, pubkey })`: verifies a `{ s, e }` signature.

### Serialization (`./src/serialization.ts`)

JSON-friendly (hex/decimal string) wire forms for every DKG and signing type, so packages can cross network/storage boundaries:

- `serializeDkgRound1` / `deserializeDkgRound1`
- `serializeDkgRound2` / `deserializeDkgRound2`
- `serializeDkgRound3` / `deserializeDkgRound3`
- `serializeNonceCommitments` / `deserializeNonceCommitments`
- `serializeNonces` / `deserializeNonces`
- `serializeSignatureShare` / `deserializeSignatureShare`
- `serializeSchnorrSignature` / `deserializeSchnorrSignature`

### Poseidon (`./src/poseidon.ts`)

- `poseidon(inputs: bigint[])`: Poseidon hash over the BabyJubJub base field, parameterized to be compatible with [`circomlibjs`](https://github.com/iden3/circomlibjs) / [`circomlib`](https://github.com/iden3/circomlib)'s Poseidon — i.e. the same hash a circom circuit using `circomlib`'s `Poseidon` template will compute.

### Utils (`./src/utils.ts`)

- `mod(a, n)`: non-negative modulo (`((a % n) + n) % n`).
- `randomScalar()`: cryptographically random scalar in `[0, ORDER)`, suitable for nonces/secrets.

## License

MIT
