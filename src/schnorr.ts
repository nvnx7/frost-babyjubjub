import { babyjubjub } from "@noble/curves/misc.js";
import { poseidon } from "./poseidon";
import { bytesToNumberBE, randomBytes } from "@noble/curves/utils.js";
import { mod } from "./utils";
import { BASE, ORDER } from "./babyjubjub";

export type SchnorrSignature = { s: bigint; e: bigint };

function randomScalar(): bigint {
	// Draw 48 bytes before reducing so the modulo bias mod ORDER is negligible.
	const bytes = randomBytes(48);
	return mod(bytesToNumberBE(bytes), ORDER);
}

export const schnorrSign = (params: {
	message: bigint;
	key: bigint;
}): SchnorrSignature => {
	const { message, key } = params;
	const pubkey = BASE.multiply(mod(key, ORDER));
	const k = randomScalar();
	const R = BASE.multiply(mod(k, ORDER));
	const e = poseidon([R.x, R.y, pubkey.x, pubkey.y, message]);
	const s = mod(k - mod(e * key, ORDER), ORDER);
	return { s, e };
};

export const schnorrVerify = (params: {
	message: bigint;
	signature: SchnorrSignature;
	pubkey: { x: bigint; y: bigint };
}): boolean => {
	const { message, signature: sig, pubkey } = params;
	const pubPt = babyjubjub.Point.fromAffine(pubkey);
	const R = BASE.multiply(mod(sig.s, ORDER)).add(
		pubPt.multiply(mod(sig.e, ORDER)),
	);
	const ePrime = poseidon([R.x, R.y, pubkey.x, pubkey.y, message]);
	return ePrime === sig.e;
};
