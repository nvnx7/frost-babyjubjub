import { describe, expect, it } from "bun:test";
import type { DKG_Round2, Key } from "@noble/curves/abstract/frost.js";
import { babyjubjub } from "@noble/curves/misc.js";
import {
  deserializeDkgRound1,
  deserializeDkgRound3,
  dkgRound1,
  dkgRound2,
  dkgRound3,
  frostAggregate,
  frostCommit,
  frostSign,
  frostVerifyShare,
  poseidon,
  schnorrVerify,
  serializeDkgRound1,
  serializeDkgRound3,
} from "../src/index";

/** Runs a full 2-of-3 DKG with the native (unserialized) round API. */
function setupDKG() {
  const threshold = 2;
  const total = 3;
  const addrs = { alice: "alice", bob: "bob", carol: "carol" } as const;

  const r1 = {
    alice: dkgRound1({ address: addrs.alice, threshold, total }),
    bob: dkgRound1({ address: addrs.bob, threshold, total }),
    carol: dkgRound1({ address: addrs.carol, threshold, total }),
  };

  const othersR1 = {
    alice: [r1.bob.public, r1.carol.public],
    bob: [r1.alice.public, r1.carol.public],
    carol: [r1.alice.public, r1.bob.public],
  };

  const r2 = {
    alice: dkgRound2({
      myRound1Secret: r1.alice.secret,
      othersRound1Public: othersR1.alice,
    }),
    bob: dkgRound2({
      myRound1Secret: r1.bob.secret,
      othersRound1Public: othersR1.bob,
    }),
    carol: dkgRound2({
      myRound1Secret: r1.carol.secret,
      othersRound1Public: othersR1.carol,
    }),
  };

  const id = {
    alice: r1.alice.public.identifier,
    bob: r1.bob.public.identifier,
    carol: r1.carol.public.identifier,
  };

  const aliceKey = dkgRound3({
    myRound1Secret: r1.alice.secret,
    othersRound1Public: othersR1.alice,
    othersRound2Public: [r2.bob[id.alice], r2.carol[id.alice]] as DKG_Round2[],
  });
  const bobKey = dkgRound3({
    myRound1Secret: r1.bob.secret,
    othersRound1Public: othersR1.bob,
    othersRound2Public: [r2.alice[id.bob], r2.carol[id.bob]] as DKG_Round2[],
  });
  const carolKey = dkgRound3({
    myRound1Secret: r1.carol.secret,
    othersRound1Public: othersR1.carol,
    othersRound2Public: [r2.alice[id.carol], r2.bob[id.carol]] as DKG_Round2[],
  });

  return { aliceKey, bobKey, carolKey, id };
}

function groupPubkey(key: Key) {
  const pk = babyjubjub.Point.fromBytes(
    key.public.commitments[0] as Uint8Array,
  ).toAffine();
  return { x: pk.x, y: pk.y };
}

describe("FROST DKG", () => {
  it("produces a single shared group public key across participants", () => {
    const { aliceKey, bobKey, carolKey } = setupDKG();
    expect(aliceKey.public.commitments[0]).toEqual(
      bobKey.public.commitments[0],
    );
    expect(aliceKey.public.commitments[0]).toEqual(
      carolKey.public.commitments[0],
    );
  });

  it("round1 serialization round-trips", () => {
    const r1 = dkgRound1({ address: "alice", threshold: 2, total: 3 });
    const restored = deserializeDkgRound1(serializeDkgRound1(r1));
    expect(restored.public.identifier).toBe(r1.public.identifier);
    expect(restored.secret.identifier).toBe(r1.secret.identifier);
    expect(restored.public.commitment).toEqual(r1.public.commitment);
  });

  it("round3 key serialization round-trips", () => {
    const { aliceKey } = setupDKG();
    const restored = deserializeDkgRound3(serializeDkgRound3(aliceKey));
    expect(restored.public.commitments[0]).toEqual(
      aliceKey.public.commitments[0],
    );
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

    const aShare = frostSign(
      aliceKey.secret,
      aliceKey.public,
      a.nonces,
      commitmentList,
      msg,
    );
    const bShare = frostSign(
      bobKey.secret,
      bobKey.public,
      b.nonces,
      commitmentList,
      msg,
    );

    expect(
      frostVerifyShare(
        aliceKey.public,
        commitmentList,
        msg,
        aShare.identifier,
        aShare.z,
      ),
    ).toBe(true);

    const sig = frostAggregate(aliceKey.public, commitmentList, msg, [
      aShare,
      bShare,
    ]);
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

    const aShare = frostSign(
      aliceKey.secret,
      aliceKey.public,
      a.nonces,
      listA,
      msg,
    );
    const bShare = frostSign(
      bobKey.secret,
      bobKey.public,
      b.nonces,
      listB,
      msg,
    );
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
    expect(() =>
      frostSign(aliceKey.secret, aliceKey.public, a.nonces, list, msg),
    ).toThrow();
  });

  it("aggregate attributes a cheating signer", () => {
    const { aliceKey, bobKey } = setupDKG();
    const msg = poseidon([2n]);
    const a = frostCommit(aliceKey.secret);
    const b = frostCommit(bobKey.secret);
    const list = [a.commitments, b.commitments];
    const aShare = frostSign(
      aliceKey.secret,
      aliceKey.public,
      a.nonces,
      list,
      msg,
    );
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
