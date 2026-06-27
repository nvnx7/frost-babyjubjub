import { describe, expect, it } from "bun:test";
import {
	schnorrSign,
	schnorrVerify,
	mod,
	poseidon,
} from "../src";
import { BASE, ORDER } from "../src/babyjubjub";

describe("Schnorr (Poseidon challenge, s = k - e*sk)", () => {
	const key = 12345678901234567890n;
	const pubPt = BASE.multiply(mod(key, ORDER)).toAffine();
	const pubkey = { x: pubPt.x, y: pubPt.y };
	const message = poseidon([1n, 2n, 3n]);

	it("a valid signature verifies", () => {
		const sig = schnorrSign({ secretKey: key, message });
		expect(schnorrVerify({ signature: sig, pubkey, message })).toBe(true);
	});

	it("a wrong message fails", () => {
		const sig = schnorrSign({ secretKey: key, message });
		expect(
			schnorrVerify({ signature: sig, pubkey, message: message + 1n }),
		).toBe(false);
	});

	it("a wrong public key fails", () => {
		const sig = schnorrSign({ secretKey: key, message });
		const otherPt = BASE.multiply(mod(999n, ORDER)).toAffine();
		expect(
			schnorrVerify({
				signature: sig,
				pubkey: { x: otherPt.x, y: otherPt.y },
				message,
			}),
		).toBe(false);
	});

	it("a tampered s fails", () => {
		const sig = schnorrSign({ secretKey: key, message });
		expect(
			schnorrVerify({
				signature: { s: mod(sig.s + 1n, ORDER), e: sig.e },
				pubkey,
				message,
			}),
		).toBe(false);
	});
});
