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

import type { EdwardsPoint } from "@noble/curves/abstract/edwards.js";
import { createFROST } from "@noble/curves/abstract/frost.js";
import { babyjubjub } from "@noble/curves/misc.js";
import { bytesToNumberBE } from "@noble/curves/utils.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { poseidon } from "./poseidon";
import { mod } from "./utils";

type P = EdwardsPoint;

export const ORDER = babyjubjub.Point.CURVE().n;
export const BASE = babyjubjub.Point.BASE;
export const Fn = babyjubjub.Point.Fn;

function challenge(R: P, PK: P, msg: Uint8Array): bigint {
  return mod(poseidon([R.x, R.y, PK.x, PK.y, bytesToNumberBE(msg)]), ORDER);
}

export const babyjubjub_FROST = createFROST({
  name: "FROST-BABYJUBJUB-SHA512-v1",
  Point: babyjubjub.Point,
  hash: sha512,
  challenge,
});
