pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "./lib/bn254.circom";
include "./lib/curve.circom";

template Cassiopeia() {
  signal input secret; // The secret (field value) in little endian
  signal input concat[2]; // Two halves of H(ciphertext || instance)
  signal output H;
  signal output F_0[2];

  // Prove knowledge of preimage of hash
  component poseidon = Poseidon(3);
  poseidon.inputs[0] <== secret;
  poseidon.inputs[1] <== concat[0];
  poseidon.inputs[2] <== concat[1];
  H <== poseidon.out;

  var b = 3; // B for G1 of BN254 is 3
  var p[5] = bn254_p();
  component bn254_multiplier = EllipticCurveScalarMultiplySignalX(51, 5, b, p);

  // Generator for BN254 is (1, 2);
  bn254_multiplier.in[0][0] <== 1;
  bn254_multiplier.in[1][0] <== 2;
  for (var i = 1; i < 5; i++) {
    bn254_multiplier.in[0][i] <== 0;
    bn254_multiplier.in[1][i] <== 0;
  }

  bn254_multiplier.inIsInfinity <== 0;
  bn254_multiplier.x <== secret;

  var shifts[5];
  for (var i = 0; i < 5; i++) shifts[i] = 1 << (51 * i);
  var x_out = 0;
  var y_out = 0;
  for (var i = 0; i < 5; i++) {
    x_out += bn254_multiplier.out[0][i] * shifts[i];
    y_out += bn254_multiplier.out[1][i] * shifts[i];
  }

  x_out ==> F_0[0];
  y_out ==> F_0[1];
}

component main {public [concat]} = Cassiopeia();
