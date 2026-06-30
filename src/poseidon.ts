import type { PoseidonFn } from "@noble/curves/abstract/poseidon.js";
import {
	grainGenConstants,
	poseidon as noblePoseidon,
} from "@noble/curves/abstract/poseidon.js";
import { babyjubjub } from "@noble/curves/misc.js";

// The BabyJubJub prime field. All Poseidon inputs and outputs live in this field.
const Fp = babyjubjub.Point.Fp;

// Partial round counts per permutation width t=2..17 (index = t-2).
// Source: circomlibjs / iden3 poseidon_opt.js
const N_ROUNDS_P: Record<number, number> = {
	2: 56,
	3: 57,
	4: 56,
	5: 60,
	6: 60,
	7: 63,
	8: 64,
	9: 63,
	10: 60,
	11: 66,
	12: 60,
	13: 65,
	14: 70,
	15: 60,
	16: 64,
	17: 68,
};

// Lazily constructed permutation instances, keyed by t.
const permutationCache = new Map<number, PoseidonFn>();

function getPermutation(t: number): PoseidonFn {
	const cached = permutationCache.get(t);
	if (cached) return cached;

	const roundsPartial = N_ROUNDS_P[t];
	if (roundsPartial === undefined)
		throw new Error(`poseidon: unsupported width t=${t}`);

	const constants = grainGenConstants({
		Fp,
		t,
		roundsFull: 8,
		roundsPartial,
		sboxPower: 5,
	});

	const perm = noblePoseidon({
		...constants,
		Fp,
		t,
		roundsFull: 8,
		roundsPartial,
		sboxPower: 5,
	});

	permutationCache.set(t, perm);
	return perm;
}

/**
 * Poseidon hash over the BabyJubJub field.
 * Compatible with circomlibjs / iden3 Poseidon.
 *
 * @param inputs - 1 to 16 field elements (bigints in [0, Fp.ORDER)).
 * @returns Single field element digest.
 */
export function poseidon(inputs: bigint[]): bigint {
	if (inputs.length < 1 || inputs.length > 16)
		throw new RangeError(
			`poseidon: expected 1–16 inputs, got ${inputs.length}`,
		);

	for (const x of inputs) {
		if (typeof x !== "bigint" || x < 0n || x >= Fp.ORDER)
			throw new RangeError(
				`poseidon: input ${x} is out of field range [0, Fp.ORDER)`,
			);
	}

	// State layout: [capacity=0, input_0, ..., input_n-1]
	return getPermutation(inputs.length + 1)([0n, ...inputs])[0]!;
}
