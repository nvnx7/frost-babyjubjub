import { babyjubjub } from "@noble/curves/misc.js";
import { bytesToNumberBE, randomBytes } from "@noble/curves/utils.js";

const n = bytesToNumberBE(randomBytes(31));
console.log("Random scalar n:", n.toString(10));

const p = babyjubjub.Point.BASE.multiply(n);
const pAff = p.toAffine();
console.log("P.x", pAff.x.toString());
console.log("P.y", pAff.y.toString());

const pBytes = p.toBytes();
console.log("P bytes:", pBytes);

const p2 = babyjubjub.Point.fromBytes(pBytes);
const p2Aff = p2.toAffine();
console.log("P2.x", p2Aff.x.toString());
console.log("P2.y", p2Aff.y.toString());

const isSame = p.equals(p2);
console.log("P equals P2:", isSame);
