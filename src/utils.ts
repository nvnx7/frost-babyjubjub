import { bytesToNumberBE, randomBytes } from "@noble/curves/utils.js";
import { ORDER } from "./babyjubjub";

export function mod(a: bigint, n: bigint): bigint {
	const res = a % n;
	return res < 0n ? res + n : res;
}

export function randomScalar(): bigint {
	// 48 bytes before reducing → negligible modulo bias.
	return mod(bytesToNumberBE(randomBytes(48)), ORDER);
}
