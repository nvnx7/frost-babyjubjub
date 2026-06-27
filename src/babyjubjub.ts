/**
 * BabyJubJub FROST instance (RFC 9591).
 *
 * Used ONLY for Distributed Key Generation (DKG rounds 1–3).
 * Do NOT use bjj_FROST.signShare / aggregate / verify for circuit-compatible
 * signatures — those use the RFC 9591 sign equation (z = r + c·sk) which is
 * incompatible with schnorr_verify.circom (s = k − e·sk).
 *
 * For signing, use the functions in ./signature.ts instead.
 */
import { babyjubjub } from "@noble/curves/misc.js";
import { createFROST } from "@noble/curves/abstract/frost.js";
import { sha256 } from "@noble/hashes/sha2.js";

export const babyjubjub_FROST = createFROST({
	name: "babyjubjub-frost",
	Point: babyjubjub.Point,
	// noble's CHash types its output as Uint8Array<ArrayBufferLike>, which doesn't
	// structurally match createFROST's ArrayBuffer-branded hash signature.
	hash: sha256,
});

export const ORDER = babyjubjub.Point.CURVE().n;
export const BASE = babyjubjub.Point.BASE;
