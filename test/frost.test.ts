import { describe, expect, it } from "bun:test";
import { babyjubjub } from "@noble/curves/misc.js";
import type { DKG_Round2, Key } from "@noble/curves/abstract/frost.js";
import {
  serializeDkgRound1,
  deserializeDkgRound1,
  serializeDkgRound3,
  deserializeDkgRound3,
  frostCommit,
  frostSign,
  frostAggregate,
  frostVerifyShare,
  schnorrVerify,
  poseidon,
} from "../src/index";
import { babyjubjub_FROST } from "../src/babyjubjub";

/** Runs a full 2-of-3 DKG with the native (unserialized) round API. */
function setupDKG() {
  const threshold = 2;
  const total = 3;
  const addrs = { alice: "alice", bob: "bob", carol: "carol" } as const;

  const r1 = {
    alice: babyjubjub_FROST.DKG.round1(babyjubjub_FROST.Identifier.derive(addrs.alice), { min: threshold, max: total }),
    bob: babyjubjub_FROST.DKG.round1(babyjubjub_FROST.Identifier.derive(addrs.bob), { min: threshold, max: total }),
    carol: babyjubjub_FROST.DKG.round1(babyjubjub_FROST.Identifier.derive(addrs.carol), { min: threshold, max: total }),
  };

  const othersR1 = {
    alice: [r1.bob.public, r1.carol.public],
    bob: [r1.alice.public, r1.carol.public],
    carol: [r1.alice.public, r1.bob.public],
  };

  const r2 = {
    alice: babyjubjub_FROST.DKG.round2(r1.alice.secret, othersR1.alice),
    bob: babyjubjub_FROST.DKG.round2(r1.bob.secret, othersR1.bob),
    carol: babyjubjub_FROST.DKG.round2(r1.carol.secret, othersR1.carol),
  };

  const id = {
    alice: babyjubjub_FROST.Identifier.derive(addrs.alice),
    bob: babyjubjub_FROST.Identifier.derive(addrs.bob),
    carol: babyjubjub_FROST.Identifier.derive(addrs.carol),
  };

  const aliceKey = babyjubjub_FROST.DKG.round3(r1.alice.secret, othersR1.alice, [r2.bob[id.alice], r2.carol[id.alice]] as DKG_Round2[]);
  const bobKey = babyjubjub_FROST.DKG.round3(r1.bob.secret, othersR1.bob, [r2.alice[id.bob], r2.carol[id.bob]] as DKG_Round2[]);
  const carolKey = babyjubjub_FROST.DKG.round3(r1.carol.secret, othersR1.carol, [r2.alice[id.carol], r2.bob[id.carol]] as DKG_Round2[]);

  return { aliceKey, bobKey, carolKey, id };
}

function groupPubkey(key: Key) {
  const pk = babyjubjub.Point.fromBytes(key.public.commitments[0] as Uint8Array).toAffine();
  return { x: pk.x, y: pk.y };
}

describe("FROST DKG", () => {
  it("produces a single shared group public key across participants", () => {
    const { aliceKey, bobKey, carolKey } = setupDKG();
    expect(aliceKey.public.commitments[0]).toEqual(bobKey.public.commitments[0]);
    expect(aliceKey.public.commitments[0]).toEqual(carolKey.public.commitments[0]);
  });

  it("round1 serialization round-trips", () => {
    const r1 = babyjubjub_FROST.DKG.round1(babyjubjub_FROST.Identifier.derive("alice"), { min: 2, max: 3 });
    const restored = deserializeDkgRound1(serializeDkgRound1(r1));
    expect(restored.public.identifier).toBe(r1.public.identifier);
    expect(restored.secret.identifier).toBe(r1.secret.identifier);
    expect(restored.public.commitment).toEqual(r1.public.commitment);
  });

  it("round3 key serialization round-trips", () => {
    const { aliceKey } = setupDKG();
    const restored = deserializeDkgRound3(serializeDkgRound3(aliceKey));
    expect(restored.public.commitments[0]).toEqual(aliceKey.public.commitments[0]);
    expect(restored.secret.signingShare).toEqual(aliceKey.secret.signingShare);
  });
});

describe("FROST signing (circuit-compatible)", () => {
  it("a 2-of-3 aggregated signature verifies against the group key", () => {
    const { aliceKey, bobKey } = setupDKG();
    const pubkey = groupPubkey(aliceKey);
    const msg = poseidon([312312312n]);

    const a = frostCommit(aliceKey.secret);
    const b = frostCommit(bobKey.secret);
    const commitmentList = [a.commitments, b.commitments];

    const aShare = frostSign(aliceKey.secret, aliceKey.public, a.nonces, commitmentList, msg);
    const bShare = frostSign(bobKey.secret, bobKey.public, b.nonces, commitmentList, msg);

    expect(frostVerifyShare(aliceKey.public, commitmentList, msg, aShare.identifier, aShare.z)).toBe(true);

    const sig = frostAggregate(aliceKey.public, commitmentList, msg, [aShare, bShare]);
    expect(schnorrVerify({ message: msg, signature: sig, pubkey })).toBe(true);
  });

  it("verifies regardless of commitment-list ordering between signers", () => {
    const { aliceKey, bobKey } = setupDKG();
    const pubkey = groupPubkey(aliceKey);
    const msg = poseidon([7n]);

    const a = frostCommit(aliceKey.secret);
    const b = frostCommit(bobKey.secret);
    const listA = [a.commitments, b.commitments];
    const listB = [b.commitments, a.commitments]; // bob orders differently

    const aShare = frostSign(aliceKey.secret, aliceKey.public, a.nonces, listA, msg);
    const bShare = frostSign(bobKey.secret, bobKey.public, b.nonces, listB, msg);
    const sig = frostAggregate(aliceKey.public, listA, msg, [aShare, bShare]);

    expect(schnorrVerify({ message: msg, signature: sig, pubkey })).toBe(true);
  });

  it("rejects a reused nonce", () => {
    const { aliceKey, bobKey } = setupDKG();
    const msg = poseidon([1n]);
    const a = frostCommit(aliceKey.secret);
    const b = frostCommit(bobKey.secret);
    const list = [a.commitments, b.commitments];
    frostSign(aliceKey.secret, aliceKey.public, a.nonces, list, msg); // consumes a.nonces
    expect(() => frostSign(aliceKey.secret, aliceKey.public, a.nonces, list, msg)).toThrow();
  });

  it("aggregate attributes a cheating signer", () => {
    const { aliceKey, bobKey } = setupDKG();
    const msg = poseidon([2n]);
    const a = frostCommit(aliceKey.secret);
    const b = frostCommit(bobKey.secret);
    const list = [a.commitments, b.commitments];
    const aShare = frostSign(aliceKey.secret, aliceKey.public, a.nonces, list, msg);
    const bShare = frostSign(bobKey.secret, bobKey.public, b.nonces, list, msg);
    const badB = { ...bShare, z: bShare.z + 1n };

    try {
      frostAggregate(aliceKey.public, list, msg, [aShare, badB]);
      throw new Error("expected aggregation to fail");
    } catch (e: any) {
      expect(e.cheaters).toEqual([bShare.identifier]);
    }
  });
});
