import { describe, expect, test } from "bun:test";
import {
	deserializeFrostSignature,
	deserializeNonceCommitments,
	deserializeNonces,
	deserializeSignatureShare,
	dkgRound1,
	dkgRound2,
	dkgRound3,
	frostCommit,
	serializeFrostSignature,
	serializeNonceCommitments,
	serializeNonces,
	serializeSignatureShare,
} from "../src/index";
import { babyjubjub_FROST } from "../src/babyjubjub";

function aliceKey() {
	// 2-of-2 DKG to obtain a usable FrostSecret for frostCommit.
	const a = dkgRound1({ address: "alice", threshold: 2, total: 2 });
	const b = dkgRound1({ address: "bob", threshold: 2, total: 2 });
	const aR2 = dkgRound2({
		myRound1Secret: a.secret,
		othersRound1Public: [b.public],
	});
	const bR2 = dkgRound2({
		myRound1Secret: b.secret,
		othersRound1Public: [a.public],
	});
	const aliceId = babyjubjub_FROST.Identifier.derive("alice");
	return dkgRound3({
		myRound1Secret: a.secret,
		othersRound1Public: [b.public],
		othersRound2Public: [bR2[aliceId]!],
	});
}

describe("sign-phase serialization", () => {
	test("nonce commitments + nonces round-trip from frostCommit", () => {
		const { nonces, commitments } = frostCommit(aliceKey().secret);

		const c2 = deserializeNonceCommitments(
			serializeNonceCommitments(commitments),
		);
		expect(c2.identifier).toBe(commitments.identifier);
		expect(c2.hiding).toEqual(commitments.hiding);
		expect(c2.binding).toEqual(commitments.binding);

		const n2 = deserializeNonces(serializeNonces(nonces));
		expect(n2.hiding).toEqual(nonces.hiding);
		expect(n2.binding).toEqual(nonces.binding);
	});

	test("signature share + frost signature round-trip", () => {
		const share = { identifier: "0a", z: 1234567890123456789n };
		expect(deserializeSignatureShare(serializeSignatureShare(share))).toEqual(
			share,
		);

		const sig = { s: 111n, e: 222n };
		expect(deserializeFrostSignature(serializeFrostSignature(sig))).toEqual(
			sig,
		);
	});
});
