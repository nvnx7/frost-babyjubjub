/**
 * Circuit-compatible FROST signing layer.
 *
 * Uses the same DKG key shares produced by babyjubjub_FROST, and
 * the resulting (s, e) signature is verifiable inside circom circuit.
 *
 * RFC 9591 produces z = r + c·sk with verify z·G − c·PK = R, which is the
 * same equation as s = k + e·sk / R = s·G − e·PK (s = z, e = c). The `e`
 * returned here is the raw Poseidon digest (not reduced mod the subgroup
 * order) so it matches schnorr_verify.circom's recomputed challenge exactly.
 * Only this module should be used for producing signatures that go into the
 * SNARK circuit.
 */

import type {
	FrostPublic,
	FrostSecret,
	NonceCommitments,
	Nonces,
} from "@noble/curves/abstract/frost.js";
import { babyjubjub } from "@noble/curves/misc.js";
import { numberToBytesBE } from "@noble/curves/utils.js";
import { babyjubjub_FROST, Fn } from "./babyjubjub";
import { poseidon } from "./poseidon";

/**
 * Decodes and validates a serialized point (mirror of babyjubjub_FROST parsePoint, with
 * the subgroup/identity policy a Section 6 ciphersuite installs via
 * `validatePoint`). Rejects the identity and any point outside the prime-order
 * subgroup — either would otherwise let a malformed commitment or key through.
 */
function parsePoint(bytes: Uint8Array) {
	const p = babyjubjub.Point.fromBytes(bytes); // canonical + on-curve
	if (p.is0()) throw new Error("invalid point: identity element");
	if (!p.isTorsionFree())
		throw new Error("invalid point: not in prime-order subgroup");
	return p;
}

/**
 * Round 1: generate nonce pair and return commitment.
 * Mirrors bjj_FROST.commit — takes the participant's secret share package and
 * derives the hiding/binding nonces from it.
 */
export function frostCommit(secret: FrostSecret): {
	nonces: Nonces;
	commitments: NonceCommitments;
} {
	return babyjubjub_FROST.commit(secret);
}

export function frostSign(
	secret: FrostSecret,
	pub: FrostPublic,
	nonces: Nonces,
	commitmentList: NonceCommitments[],
	msg: bigint,
) {
	const share = babyjubjub_FROST.signShare(
		secret,
		pub,
		nonces,
		commitmentList,
		numberToBytesBE(msg, 32),
	);

	return {
		identifier: secret.identifier,
		z: Fn.fromBytes(share),
	};
}

export function frostVerifyShare(
	pub: FrostPublic,
	commitmentList: NonceCommitments[],
	msg: bigint,
	identifier: string,
	sigShare: bigint,
) {
	return babyjubjub_FROST.verifyShare(
		pub,
		commitmentList,
		numberToBytesBE(msg, 32),
		identifier,
		// sigShare,
		Fn.toBytes(sigShare),
	);
}

export function frostAggregate(
	pub: FrostPublic,
	commitmentList: NonceCommitments[],
	msg: bigint,
	shares: { identifier: string; z: bigint }[],
) {
	const sharesBytes: Record<string, Uint8Array> = {};
	for (const s of shares) {
		sharesBytes[s.identifier] = Fn.toBytes(s.z);
	}
	const sig = babyjubjub_FROST.aggregate(
		pub,
		commitmentList,
		numberToBytesBE(msg, 32),
		sharesBytes,
	);
	const R = parsePoint(sig.subarray(0, -Fn.BYTES));
	const z = Fn.fromBytes(sig.subarray(-Fn.BYTES));
	const gpk = parsePoint(pub.commitments[0] as Uint8Array);
	const e = poseidon([R.x, R.y, gpk.x, gpk.y, msg]);
	return { s: z, e };
}
