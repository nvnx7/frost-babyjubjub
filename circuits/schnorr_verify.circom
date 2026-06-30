pragma circom 2.2.3;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/escalarmulany.circom";
include "../node_modules/circomlib/circuits/babyjub.circom";

/// @title SchnorrVerify
/// @notice Verifies a BabyJubJub Schnorr signature (s, e) over `msg` with `pubkey`.
///
/// Convention (matches schnorr.ts and frostAggregate):
///   Signing:      e = Poseidon(k·G_x, k·G_y, pubkey_x, pubkey_y, msg)
///                 s = k + e·privkey  (mod subgroup_order)
///   Verification: R = s·G - e·pubkey
///                 e' = Poseidon(R_x, R_y, pubkey_x, pubkey_y, msg)
///                 assert e == e'
///
/// This Poseidon-based challenge makes verification ZK-cheap (~2k constraints).
/// Compatible with our FROST instantiation which uses the same challenge hash.
///
/// @param enabled  Set to 1 to enforce the check, 0 to skip (for optional inputs).
template SchnorrVerify() {
    signal input enabled;
    signal input msg;
    signal input pubkey[2];
    signal input s;
    signal input e;

    // BabyJubJub base point G (https://eips.ethereum.org/EIPS/eip-2494)
    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    component sbits = Num2Bits(254);
    sbits.in <== s;

    component ebits = Num2Bits(254);
    ebits.in <== e;

    // Compute s·G
    component sMulG = EscalarMulAny(254);
    sMulG.e <== sbits.out;
    for (var i = 0; i < 2; i++) {
        sMulG.p[i] <== BASE8[i];
    }

    // Compute e·pubkey
    component eMulP = EscalarMulAny(254);
    eMulP.e <== ebits.out;
    eMulP.p[0] <== pubkey[0];
    eMulP.p[1] <== pubkey[1];

    // Compute R = s·G - e·pubkey = s·G + (-e·pubkey)
    // Edwards negation: (x, y) → (-x, y)
    component R = BabyAdd();
    R.x1 <== sMulG.out[0];
    R.y1 <== sMulG.out[1];
    R.x2 <== 0 - eMulP.out[0];
    R.y2 <== eMulP.out[1];

    // Compute challenge e' = Poseidon(R_x, R_y, pubkey_x, pubkey_y, msg)
    // Including pubkey in the hash binds the signature to the specific key (prevents
    // cross-key attacks in multi-key settings).
    component challenge = Poseidon(5);
    challenge.inputs[0] <== R.xout;
    challenge.inputs[1] <== R.yout;
    challenge.inputs[2] <== pubkey[0];
    challenge.inputs[3] <== pubkey[1];
    challenge.inputs[4] <== msg;

    // Assert e == e' when enabled
    component eq = ForceEqualIfEnabled();
    eq.enabled  <== enabled;
    eq.in[0]    <== e;
    eq.in[1]    <== challenge.out;
}
