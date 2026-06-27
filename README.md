# frost-babyjubjub

BabyJubJub FROST Threshold Signatures and DKG (Distributed Key Generation). 

This library provides a complete implementation of FROST (Flexible Round-Optimized Schnorr Threshold signatures) over the BabyJubJub curve. 
It uses a Poseidon-based challenge and the $s = k - e \cdot sk$ signing equation, making it compatible with `schnorr_verify.circom` inside zk-SNARK circuits.

## Features
- **FROST DKG (3 Rounds)**: Generate shared group public keys and individual secret shares without a trusted dealer.
- **FROST Signing (2 Rounds)**: Produce threshold signatures that aggregate into a standard Schnorr signature.
- **Circuit-Compatible**: Uses Poseidon hashes and matching signing conventions to verify inside circom circuits.

## Quick Start

### 1. Distributed Key Generation (DKG)
A threshold setup requires $t$-of-$n$ participants (e.g. 2-of-3). The DKG process is done in 3 rounds.

```typescript
import { dkgRound1, dkgRound2, dkgRound3 } from "frost-babyjubjub";

const threshold = 2;
const total = 3;

// Round 1 (Each participant)
const aliceR1 = dkgRound1({ address: "alice", threshold, total });
const bobR1 = dkgRound1({ address: "bob", threshold, total });
const carolR1 = dkgRound1({ address: "carol", threshold, total });

// Broadcast Round 1 Public Data to all participants...

// Round 2 (Alice generates shares for others)
const aliceR2 = dkgRound2({
  myRound1Secret: aliceR1.secret,
  othersRound1Public: [bobR1.public, carolR1.public]
});
// (Bob and Carol do the same...)

// Round 3 (Compute the final key share)
const aliceKey = dkgRound3({
  myRound1Secret: aliceR1.secret,
  othersRound1Public: [bobR1.public, carolR1.public],
  othersRound2Public: [bobR2[aliceId], carolR2[aliceId]], 
});

// aliceKey contains both her secret share and the group public key!
```

### 2. Threshold Signing
Signing requires $t$ participants to interact in 2 rounds.

```typescript
import { frostCommit, frostSign, frostAggregate, poseidon } from "frost-babyjubjub";

const msg = poseidon([123n, 456n]); // The message to sign

// Round 1: Commitments
const aliceCommit = frostCommit(aliceKey.secret);
const bobCommit = frostCommit(bobKey.secret);
const commitmentList = [aliceCommit.commitments, bobCommit.commitments];

// Round 2: Signature Shares
const aliceShare = frostSign(
    aliceKey.secret, aliceKey.public, aliceCommit.nonces, commitmentList, msg
);
const bobShare = frostSign(
    bobKey.secret, bobKey.public, bobCommit.nonces, commitmentList, msg
);

// Aggregation (Can be done by anyone)
const groupSignature = frostAggregate(
    aliceKey.public, commitmentList, msg, [aliceShare, bobShare]
);
```

### 3. Verification

```typescript
import { schnorrVerify } from "frost-babyjubjub";

const isValid = schnorrVerify({
  signature: groupSignature,
  pubkey: groupPubkey, 
  message: msg
});
console.log(isValid); // true
```

## API Reference

### DKG
- `dkgRound1(opts: DkgRound1Opts)`: Generates initial public/secret values.
- `dkgRound2(opts: DkgRound2Opts)`: Computes secret shares for other participants.
- `dkgRound3(opts: DkgRound3Opts)`: Finalizes the group key and individual signing share.

### FROST Signing
- `frostCommit(secret: FrostSecret)`: Generates hiding/binding nonces and their commitments.
- `frostSign(secret, pub, nonces, commitmentList, msg)`: Generates a signature share.
- `frostAggregate(pub, commitmentList, msg, shares)`: Aggregates signature shares into a final Schnorr signature.
- `frostVerifyShare(pub, commitmentList, msg, identifier, sigShare)`: Verifies a single participant's signature share.

### Serialization
All types can be securely serialized/deserialized to share across network boundaries:
- `serializeDkgRound1` / `deserializeDkgRound1`
- `serializeDkgRound3` / `deserializeDkgRound3`
- `serializeNonceCommitments` / `deserializeNonceCommitments`
- `serializeSignatureShare` / `deserializeSignatureShare`
- `serializeFrostSignature` / `deserializeFrostSignature`

## License
MIT