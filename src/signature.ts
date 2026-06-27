/**
 * Circuit-compatible FROST signing layer.
 *
 * Uses the same DKG key shares produced by bjj_FROST (RFC 9591 DKG),
 * but signs with s = k − e·sk and e = Poseidon(R, PK, msg) so that
 * the resulting (s, e) signature is verifiable inside schnorr_verify.circom.
 *
 * The sign equation here (s = k − e·sk, verify: R = s·G + e·PK) differs
 * from RFC 9591 (z = r + c·sk, verify: z·G − c·PK = R). Only this module
 * should be used for producing signatures that go into the SNARK circuit.
 */

import { sha256, sha512 } from "@noble/hashes/sha2.js";
import {
	bytesToHex,
	bytesToNumberBE,
	bytesToNumberLE,
	concatBytes,
	hexToBytes,
	numberToBytesBE,
	randomBytes,
} from "@noble/curves/utils.js";
import { babyjubjub } from "@noble/curves/misc.js";
import type {
	FrostSecret,
	FrostPublic,
	Nonces,
	NonceCommitments,
} from "@noble/curves/abstract/frost.js";
import { poseidon } from "./poseidon";
import { mod } from "./utils";
import { BASE, ORDER } from "./babyjubjub";

export type FrostSignature = { s: bigint; e: bigint };
export type Point = { x: bigint; y: bigint };

/** A babyjubjub curve point (noble's class type), as opposed to the affine {@link Point}. */
type P = ReturnType<typeof babyjubjub.Point.fromBytes>;

// Domain-separation tags for the off-chain hashes (mirror of bjj_FROST's H1/H3/H5
// DST prefixes, i.e. `name + "rho" | "nonce" | "com"`).
const H1_RHO = new TextEncoder().encode("babyjubjub-frost-rho");
const H3_NONCE = new TextEncoder().encode("babyjubjub-frost-nonce");
const H5_COM = new TextEncoder().encode("babyjubjub-frost-com");

/**
 * Thrown by {@link frostAggregate} when the aggregated signature is invalid.
 * `cheaters` lists the identifiers whose shares failed per-share verification
 * (mirror of bjj_FROST's AggErr). Empty if the failure couldn't be attributed.
 */
export class FrostAggregateError extends Error {
	cheaters: string[];
	constructor(msg: string, cheaters: string[]) {
		super(msg);
		this.cheaters = cheaters;
	}
}

function bigintToBytes32(n: bigint): Uint8Array {
	return numberToBytesBE(n, 32);
}

/**
 * Decodes a FROST identifier (hex of the serialized scalar) to its numeric
 * value. babyjubjub's scalar field is little-endian, so identifiers — like
 * signing shares — must be read LE to match noble's DKG output.
 */
function identifierToScalar(identifier: string): bigint {
	return bytesToNumberLE(hexToBytes(identifier));
}

/**
 * Decodes and validates a serialized point (mirror of bjj_FROST parsePoint, with
 * the subgroup/identity policy a Section 6 ciphersuite installs via
 * `validatePoint`). Rejects the identity and any point outside the prime-order
 * subgroup — either would otherwise let a malformed commitment or key through.
 */
function parsePoint(bytes: Uint8Array): P {
	const p = babyjubjub.Point.fromBytes(bytes); // canonical + on-curve
	if (p.is0()) throw new Error("invalid point: identity element");
	if (!p.isTorsionFree())
		throw new Error("invalid point: not in prime-order subgroup");
	return p;
}

/**
 * Challenge hash (mirror of bjj_FROST Basic.challenge), but Poseidon-based so it
 * matches schnorr_verify.circom. This is the ONLY hash that enters the circuit.
 */
function challenge(R: P, PK: P, msg: bigint): bigint {
	return poseidon([R.x, R.y, PK.x, PK.y, msg]);
}

/**
 * Mirror of bjj_FROST getGroupCommitment (RFC 9591 §4.3–4.5): canonicalises the
 * commitment list by identifier, derives every binding factor, and accumulates
 * the group commitment. Sorting makes the binding factors independent of the
 * order in which commitments were collected — the fix for divergent factors.
 *
 * Uses sha256 (no H1/H4/H5 domain separators) for the binding factors because
 * they are off-chain and never enter the circuit.
 */
function getGroupCommitment(
	GPK: P,
	commitmentList: NonceCommitments[],
	msg: bigint,
) {
	const CL = commitmentList.map((i) => [
		i.identifier,
		identifierToScalar(i.identifier),
		parsePoint(i.hiding as Uint8Array),
		parsePoint(i.binding as Uint8Array),
	]) as [string, bigint, P, P][];
	// RFC 9591 §4.3/5.2: commitment_list is sorted by identifier.
	CL.sort((a, b) => (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
	// Encode commitment list (mirror of H5(encode_group_commitment_list(CL))).
	const Cbytes: Uint8Array[] = [];
	for (const [_, id, hC, bC] of CL)
		Cbytes.push(numberToBytesBE(id, 32), hC.toBytes(), bC.toBytes());
	const encodedCommitmentHash = sha256(concatBytes(H5_COM, ...Cbytes));
	const rhoPrefix = concatBytes(
		GPK.toBytes(),
		bigintToBytes32(msg),
		encodedCommitmentHash,
	);
	// Compute binding factors
	const bindingFactors: Record<string, bigint> = {};
	for (const [i, id] of CL) {
		bindingFactors[i] = mod(
			bytesToNumberBE(
				sha256(concatBytes(H1_RHO, rhoPrefix, numberToBytesBE(id, 32))),
			),
			ORDER,
		);
	}
	let groupCommitment = babyjubjub.Point.ZERO;
	for (const [i, _, hC, bC] of CL) {
		if (babyjubjub.Point.ZERO.equals(hC) || babyjubjub.Point.ZERO.equals(bC))
			throw new Error("infinity commitment");
		// GC += hC + bC*bindingFactor
		groupCommitment = groupCommitment.add(
			hC.add(bC.multiply(bindingFactors[i]!)),
		);
	}
	const identifiers = CL.map((i) => i[1]);
	return { identifiers, groupCommitment, bindingFactors };
}

function modPow(base: bigint, exp: bigint, mod_: bigint): bigint {
	let result = 1n;
	base = ((base % mod_) + mod_) % mod_;
	while (exp > 0n) {
		if (exp & 1n) result = (result * base) % mod_;
		base = (base * base) % mod_;
		exp >>= 1n;
	}
	return result;
}

/** Lagrange coefficient for participant `index` over the set `indices` at x=0. */
export function lagrange(index: bigint, indices: bigint[]): bigint {
	// Mirror of deriveInterpolatingValue's validation: no duplicate x-coordinates,
	// and `index` must be one of them.
	const set = new Set(indices);
	if (set.size !== indices.length) throw new Error("invalid parameters");
	if (!set.has(index)) throw new Error("invalid parameters");
	let num = 1n;
	let den = 1n;
	for (const j of indices) {
		if (j === index) continue;
		num = mod(num * mod(-j, ORDER), ORDER);
		den = mod(den * mod(index - j, ORDER), ORDER);
	}
	return mod(num * modPow(den, ORDER - 2n, ORDER), ORDER);
}

/**
 * RFC 9591 §4.1 nonce_generate: hash fresh randomness together with the signing
 * share so nonces stay unpredictable even if the RNG is weak or replayed (a
 * repeated nonce across messages would leak the signing share).
 */
function generateNonce(secretScalar: bigint): bigint {
	// F4: reduce a 512-bit hash (not 256-bit) so the nonce is ~uniform mod ORDER.
	// A biased Schnorr nonce can leak the signing share over many signatures.
	const wide = sha512(
		concatBytes(H3_NONCE, randomBytes(32), bigintToBytes32(secretScalar)),
	);
	return mod(bytesToNumberBE(wide), ORDER);
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
	const secretScalar = mod(
		bytesToNumberLE(secret.signingShare as Uint8Array),
		ORDER,
	);
	const hiding = generateNonce(secretScalar);
	const binding = generateNonce(secretScalar);
	const hidingCommitment = BASE.multiply(hiding).toBytes();
	const bindingCommitment = BASE.multiply(binding).toBytes();

	const nonces: Nonces = {
		hiding: numberToBytesBE(hiding, 32),
		binding: numberToBytesBE(binding, 32),
	};

	const commitments = {
		identifier: secret.identifier,
		hiding: hidingCommitment,
		binding: bindingCommitment,
	} as NonceCommitments;

	return {
		nonces,
		commitments,
	};
}

/**
 * Mirror of bjj_FROST prepareShare: derives the Lagrange coefficient, challenge,
 * binding factor and group commitment for one signer, from the public package
 * and the (sorted) commitment list. `identifiers` come back sorted, so the
 * Lagrange interpolation set is canonical too.
 */
function prepareShare(
	pub: FrostPublic,
	commitmentList: NonceCommitments[],
	msg: bigint,
	identifier: string,
) {
	const GPK = parsePoint(pub.commitments[0] as Uint8Array);
	const id = identifierToScalar(identifier);
	const { identifiers, groupCommitment, bindingFactors } = getGroupCommitment(
		GPK,
		commitmentList,
		msg,
	);
	const bindingFactor = bindingFactors[identifier]!;
	const lambda = lagrange(id, identifiers);
	return {
		lambda,
		challenge: challenge(groupCommitment, GPK, msg),
		bindingFactor,
		groupCommitment,
	};
}

/**
 * Round 2: each participant computes their signature share.
 * Uses s = k − e·sk (circuit-compatible sign convention).
 * Mirrors bjj_FROST.signShare: the signing set and group key are derived from
 * `commitmentList` and `pub` rather than passed explicitly.
 */
export function frostSign(
	secret: FrostSecret,
	pub: FrostPublic,
	nonces: Nonces,
	commitmentList: NonceCommitments[],
	msg: bigint,
) {
	const hidingNonce = bytesToNumberBE(nonces.hiding as Uint8Array);
	const bindingNonce = bytesToNumberBE(nonces.binding as Uint8Array);
	// F2: one-time-use — a consumed (zeroed) nonce pair must fail closed.
	if (hidingNonce === 0n || bindingNonce === 0n)
		throw new Error("signing nonces already used");
	// V1: the coordinator-supplied commitment for this signer must match its own nonces.
	const commitment = commitmentList.find(
		(c) => c.identifier === secret.identifier,
	);
	if (!commitment) throw new Error("missing signer commitment");
	if (
		bytesToHex(commitment.hiding as Uint8Array) !==
			bytesToHex(BASE.multiply(hidingNonce).toBytes()) ||
		bytesToHex(commitment.binding as Uint8Array) !==
			bytesToHex(BASE.multiply(bindingNonce).toBytes())
	)
		throw new Error("incorrect signer commitment");

	const SK = mod(bytesToNumberLE(secret.signingShare as Uint8Array), ORDER);
	const { lambda, challenge, bindingFactor } = prepareShare(
		pub,
		commitmentList,
		msg,
		secret.identifier,
	);
	const t = mod(mod(lambda * SK, ORDER) * challenge, ORDER); // challenge * lambda * SK
	const t2 = mod(bindingNonce * bindingFactor, ORDER); // bindingNonce * bindingFactor
	// s = k − e·sk convention: hidingNonce + t2 − t  (noble adds t for z = r + c·sk)
	const z = mod(hidingNonce + t2 - t, ORDER);
	// F2: consume the nonces in place — reuse across messages would leak the share.
	(nonces.hiding as Uint8Array).fill(0);
	(nonces.binding as Uint8Array).fill(0);
	return { identifier: secret.identifier, z };
}

/**
 * Verifies a single signature share (mirror of bjj_FROST.verifyShare, adapted to
 * the s = k − e·sk convention). Lets the aggregator attribute a bad signer.
 */
export function frostVerifyShare(
	pub: FrostPublic,
	commitmentList: NonceCommitments[],
	msg: bigint,
	identifier: string,
	sigShare: bigint,
): boolean {
	const comm = commitmentList.find((c) => c.identifier === identifier);
	if (!comm) throw new Error("cannot find identifier commitment");
	const PK = parsePoint(pub.verifyingShares[identifier] as Uint8Array); // Y_i = SK_i·G
	const hidingNonceCommitment = parsePoint(comm.hiding as Uint8Array);
	const bindingNonceCommitment = parsePoint(comm.binding as Uint8Array);
	const { lambda, challenge, bindingFactor } = prepareShare(
		pub,
		commitmentList,
		msg,
		identifier,
	);
	// commShare = hC + bC·bindingFactor
	const commShare = hidingNonceCommitment.add(
		bindingNonceCommitment.multiply(bindingFactor),
	);
	const l = BASE.multiply(mod(sigShare, ORDER)); // sigShare·G
	// s = k − e·sk convention: sigShare·G == commShare − (challenge·lambda)·Y_i
	const r = commShare.subtract(PK.multiply(mod(challenge * lambda, ORDER)));
	return l.equals(r);
}

/** Aggregates signature shares into a final (s, e) signature. */
export function frostAggregate(
	pub: FrostPublic,
	commitmentList: NonceCommitments[],
	msg: bigint,
	shares: { identifier: string; z: bigint }[],
): FrostSignature {
	const GPK = parsePoint(pub.commitments[0] as Uint8Array);
	const { groupCommitment } = getGroupCommitment(GPK, commitmentList, msg);
	let z = 0n;
	for (const sh of shares) z = mod(z + sh.z, ORDER); // z += zi
	const e = challenge(groupCommitment, GPK, msg);
	// V2: verify the aggregate (R == s·G + e·PK); on failure, attribute cheaters.
	const R = BASE.multiply(z).add(GPK.multiply(mod(e, ORDER)));
	if (!R.equals(groupCommitment)) {
		const cheaters = shares
			.filter(
				(sh) =>
					!frostVerifyShare(pub, commitmentList, msg, sh.identifier, sh.z),
			)
			.map((sh) => sh.identifier);
		throw new FrostAggregateError("aggregation failed", cheaters);
	}
	// Final signature: s = Σ zi, e = challenge(R, PK, msg).
	return { s: z, e };
}
