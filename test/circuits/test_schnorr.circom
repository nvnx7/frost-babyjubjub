pragma circom 2.2.3;

include "../../circuits/schnorr_verify.circom";

component main {public [enabled, msg, pubkey, s, e]} = SchnorrVerify();
