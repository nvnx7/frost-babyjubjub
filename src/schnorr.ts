import { babyjubjub } from "@noble/curves/misc.js";
import { BASE, ORDER } from "./babyjubjub";
import { poseidon } from "./poseidon";
import { mod, randomScalar } from "./utils";

export type SchnorrSignature = { s: bigint; e: bigint };

export const schnorrSign = (params: {
	message: bigint;
	secretKey: bigint;
}): SchnorrSignature => {
	const { message, secretKey } = params;
	const pubkey = BASE.multiply(mod(secretKey, ORDER));
	const k = randomScalar();
	const R = BASE.multiply(mod(k, ORDER));
	const e = poseidon([R.x, R.y, pubkey.x, pubkey.y, message]);
	const s = mod(k + mod(e * secretKey, ORDER), ORDER);
	return { s, e };
};

export const schnorrVerify = (params: {
	message: bigint;
	signature: SchnorrSignature;
	pubkey: { x: bigint; y: bigint };
}): boolean => {
	const { message, signature: sig, pubkey } = params;
	const pubPt = babyjubjub.Point.fromAffine(pubkey);
	const R = BASE.multiply(mod(sig.s, ORDER)).subtract(
		pubPt.multiply(mod(sig.e, ORDER)),
	);
	const ePrime = poseidon([R.x, R.y, pubkey.x, pubkey.y, message]);
	return ePrime === sig.e;
};
