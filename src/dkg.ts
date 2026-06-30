/**
 * Distributed Key Generation (DKG)
 *
 * These functions operate purely on noble's native types — they do NOT serialize
 * their output. Use the helpers in serialization.ts to move packages over the
 * wire / through storage.
 */
import type {
	DKG_Round1,
	DKG_Round2,
	DKG_Secret,
	Key,
} from "@noble/curves/abstract/frost.js";
import { babyjubjub_FROST } from "./babyjubjub";

/**
 * Round 1: generate this participant's polynomial, commitment and proof of
 * knowledge. The participant's identifier is derived from `address`.
 */
export function dkgRound1(params: {
	address: string;
	threshold: number;
	total: number;
}): { public: DKG_Round1; secret: DKG_Secret } {
	const { address, threshold, total } = params;
	const id = babyjubjub_FROST.Identifier.derive(address);
	const signers = { min: threshold, max: total };
	return babyjubjub_FROST.DKG.round1(id, signers);
}

/**
 * Round 2: given the round-1 broadcasts of the other participants, produce the
 * per-recipient signing-share packages. Mutates `myRound1Secret.step`.
 */
export function dkgRound2(params: {
	myRound1Secret: DKG_Secret;
	othersRound1Public: DKG_Round1[];
}): Record<string, DKG_Round2> {
	return babyjubjub_FROST.DKG.round2(
		params.myRound1Secret,
		params.othersRound1Public,
	);
}

/**
 * Round 3: finalize the key from the received round-1 and round-2 packages.
 * Returns this participant's final (group public key + signing share).
 */
export function dkgRound3(params: {
	myRound1Secret: DKG_Secret;
	othersRound1Public: DKG_Round1[];
	othersRound2Public: DKG_Round2[];
}): Key {
	// A stateless caller (e.g. one that reloaded `secret` from storage between
	// rounds) may hand us a secret still at step 1; round2 normally advances it.
	// Force step 2 so round3's internal state check passes either way.
	params.myRound1Secret.step = 2;
	return babyjubjub_FROST.DKG.round3(
		params.myRound1Secret,
		params.othersRound1Public,
		params.othersRound2Public,
	);
}
