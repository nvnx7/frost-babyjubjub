/**
 * (De)serialization for the DKG round packages — kept separate from the round
 * logic in babyjubjub_FROST.DKG so the protocol functions stay free of transport concerns.
 * All wire forms are JSON-friendly (hex strings / decimal strings).
 */
import type {
	DKG_Round1,
	DKG_Round2,
	DKG_Secret,
	Key,
	NonceCommitments,
	Nonces,
} from "@noble/curves/abstract/frost.js";
import { bytesToHex, hexToBytes } from "@noble/curves/utils.js";
import type { SchnorrSignature } from "./schnorr";

// ── Round 1 ────────────────────────────────────────────────────────────────

export type SerializedDKGRound1 = {
	public: {
		identifier: string;
		commitment: string[];
		proofOfKnowledge: string;
	};
	secret: {
		identifier: string;
		coefficients?: string[];
		commitment: string[];
		signers: { min: number; max: number };
		step?: 1 | 2 | 3;
	};
};

export function serializeDkgRound1(round1Result: {
	public: DKG_Round1;
	secret: DKG_Secret;
}): SerializedDKGRound1 {
	return {
		public: {
			identifier: round1Result.public.identifier,
			commitment: round1Result.public.commitment.map((c) => bytesToHex(c)),
			proofOfKnowledge: bytesToHex(round1Result.public.proofOfKnowledge),
		},
		secret: {
			identifier: round1Result.secret.identifier.toString(),
			coefficients: round1Result.secret.coefficients?.map((c) => c.toString()),
			commitment: round1Result.secret.commitment.map((c) => bytesToHex(c)),
			signers: {
				min: round1Result.secret.signers.min,
				max: round1Result.secret.signers.max,
			},
			step: round1Result.secret.step,
		},
	};
}

export function deserializeDkgRound1(data: SerializedDKGRound1): {
	public: DKG_Round1;
	secret: DKG_Secret;
} {
	return {
		public: {
			identifier: data.public.identifier,
			commitment: data.public.commitment.map(hexToBytes),
			proofOfKnowledge: hexToBytes(data.public.proofOfKnowledge),
		},
		secret: {
			identifier: BigInt(data.secret.identifier),
			coefficients: data.secret.coefficients?.map(BigInt),
			commitment: data.secret.commitment.map(hexToBytes),
			signers: {
				min: data.secret.signers.min,
				max: data.secret.signers.max,
			},
			step: data.secret.step,
		},
	};
}

// ── Round 2 ────────────────────────────────────────────────────────────────

export type SerializedDKGRound2 = Record<
	string,
	{
		identifier: string;
		signingShare: string;
	}
>;

export function serializeDkgRound2(
	data: Record<string, DKG_Round2>,
): SerializedDKGRound2 {
	const result: SerializedDKGRound2 = {};
	for (const [key, pkg] of Object.entries(data)) {
		result[key] = {
			identifier: pkg.identifier,
			signingShare: bytesToHex(pkg.signingShare),
		};
	}
	return result;
}

export function deserializeDkgRound2(
	data: SerializedDKGRound2,
): Record<string, DKG_Round2> {
	const result: Record<string, DKG_Round2> = {};
	for (const [key, pkg] of Object.entries(data)) {
		result[key] = {
			identifier: pkg.identifier,
			signingShare: hexToBytes(pkg.signingShare),
		};
	}
	return result;
}

// ── Round 3 ────────────────────────────────────────────────────────────────

export type SerializedDKGRound3 = {
	public: {
		signers: { min: number; max: number };
		commitments: string[];
		verifyingShares: Record<string, string>;
	};
	secret: {
		identifier: string;
		signingShare: string;
	};
};

export function serializeDkgRound3(key: Key): SerializedDKGRound3 {
	return {
		public: {
			signers: {
				min: key.public.signers.min,
				max: key.public.signers.max,
			},
			commitments: key.public.commitments.map((c) => bytesToHex(c)),
			verifyingShares: Object.fromEntries(
				Object.entries(key.public.verifyingShares).map(([k, v]) => [
					k,
					bytesToHex(v),
				]),
			),
		},
		secret: {
			identifier: key.secret.identifier,
			signingShare: bytesToHex(key.secret.signingShare),
		},
	};
}

export function deserializeDkgRound3(data: SerializedDKGRound3): Key {
	return {
		public: {
			signers: {
				min: data.public.signers.min,
				max: data.public.signers.max,
			},
			commitments: data.public.commitments.map(hexToBytes),
			verifyingShares: Object.fromEntries(
				Object.entries(data.public.verifyingShares).map(([k, v]) => [
					k,
					hexToBytes(v),
				]),
			),
		},
		secret: {
			identifier: data.secret.identifier,
			signingShare: hexToBytes(data.secret.signingShare),
		},
	};
}

// ── Signing: nonce commitments (public) ─────────────────────────────────────

export type SerializedNonceCommitments = {
	identifier: string;
	hiding: string;
	binding: string;
};

export function serializeNonceCommitments(
	c: NonceCommitments,
): SerializedNonceCommitments {
	return {
		identifier: c.identifier,
		hiding: bytesToHex(c.hiding as Uint8Array),
		binding: bytesToHex(c.binding as Uint8Array),
	};
}

export function deserializeNonceCommitments(
	data: SerializedNonceCommitments,
): NonceCommitments {
	return {
		identifier: data.identifier,
		hiding: hexToBytes(data.hiding),
		binding: hexToBytes(data.binding),
	} as NonceCommitments;
}

// ── Signing: nonces (secret) ────────────────────────────────────────────────

export type SerializedNonces = { hiding: string; binding: string };

export function serializeNonces(n: Nonces): SerializedNonces {
	return {
		hiding: bytesToHex(n.hiding as Uint8Array),
		binding: bytesToHex(n.binding as Uint8Array),
	};
}

export function deserializeNonces(data: SerializedNonces): Nonces {
	return {
		hiding: hexToBytes(data.hiding),
		binding: hexToBytes(data.binding),
	} as Nonces;
}

// ── Signing: signature share + aggregate signature ──────────────────────────

export type SignatureShare = { identifier: string; z: bigint };
export type SerializedSignatureShare = { identifier: string; z: string };

export function serializeSignatureShare(
	s: SignatureShare,
): SerializedSignatureShare {
	return { identifier: s.identifier, z: s.z.toString() };
}

export function deserializeSignatureShare(
	data: SerializedSignatureShare,
): SignatureShare {
	return { identifier: data.identifier, z: BigInt(data.z) };
}

export type SerializedSchnorrSignature = { s: string; e: string };

export function serializeSchnorrSignature(
	sig: SchnorrSignature,
): SerializedSchnorrSignature {
	return { s: sig.s.toString(), e: sig.e.toString() };
}

export function deserializeSchnorrSignature(
	data: SerializedSchnorrSignature,
): SchnorrSignature {
	return { s: BigInt(data.s), e: BigInt(data.e) };
}
