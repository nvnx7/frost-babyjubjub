import { beforeAll, describe, expect, it } from "bun:test";
import { join } from "node:path";
// @ts-expect-error circom_runtime ships no type declarations
import { WitnessCalculatorBuilder } from "circom_runtime";
import { mod, poseidon, schnorrSign } from "../src";
import { BASE, ORDER } from "../src/babyjubjub";

const BUILD_DIR = join(import.meta.dir, "../build/circuits");
const WASM_PATH = join(BUILD_DIR, "test_schnorr_js/test_schnorr.wasm");

type CircuitInput = {
	enabled: bigint;
	msg: bigint;
	pubkey: [bigint, bigint];
	s: bigint;
	e: bigint;
};

let wc: Awaited<ReturnType<typeof WitnessCalculatorBuilder>>;

async function check(input: CircuitInput): Promise<boolean> {
	try {
		await wc.calculateWitness(input, true);
		return true;
	} catch {
		return false;
	}
}

describe("SchnorrVerify circuit", () => {
	const sk = 12345678901234567890n;
	const pubPt = BASE.multiply(mod(sk, ORDER)).toAffine();
	const pubkey: [bigint, bigint] = [pubPt.x, pubPt.y];
	const message = poseidon([1n, 2n, 3n]);

	beforeAll(async () => {
		await Bun.$`mkdir -p ${BUILD_DIR}`.quiet();
		await Bun.$`circom test/circuits/test_schnorr.circom --wasm --r1cs -o ${BUILD_DIR} -l node_modules`.quiet();
		const wasm = new Uint8Array(await Bun.file(WASM_PATH).arrayBuffer());
		wc = await WitnessCalculatorBuilder(wasm);
	}, 60_000);

	it("accepts a valid Schnorr signature", async () => {
		const sig = schnorrSign({ secretKey: sk, message });
		expect(
			await check({ enabled: 1n, msg: message, pubkey, s: sig.s, e: sig.e }),
		).toBe(true);
	});

	it("rejects tampered s", async () => {
		const sig = schnorrSign({ secretKey: sk, message });
		expect(
			await check({
				enabled: 1n,
				msg: message,
				pubkey,
				s: mod(sig.s + 1n, ORDER),
				e: sig.e,
			}),
		).toBe(false);
	});

	it("rejects tampered e", async () => {
		const sig = schnorrSign({ secretKey: sk, message });
		expect(
			await check({
				enabled: 1n,
				msg: message,
				pubkey,
				s: sig.s,
				e: mod(sig.e + 1n, ORDER),
			}),
		).toBe(false);
	});

	it("rejects wrong pubkey", async () => {
		const sig = schnorrSign({ secretKey: sk, message });
		const otherPt = BASE.multiply(mod(999n, ORDER)).toAffine();
		expect(
			await check({
				enabled: 1n,
				msg: message,
				pubkey: [otherPt.x, otherPt.y],
				s: sig.s,
				e: sig.e,
			}),
		).toBe(false);
	});

	it("rejects wrong message", async () => {
		const sig = schnorrSign({ secretKey: sk, message });
		expect(
			await check({
				enabled: 1n,
				msg: message + 1n,
				pubkey,
				s: sig.s,
				e: sig.e,
			}),
		).toBe(false);
	});

	it("skips check when enabled=0", async () => {
		expect(
			await check({ enabled: 0n, msg: message, pubkey, s: 1n, e: 1n }),
		).toBe(true);
	});
});
