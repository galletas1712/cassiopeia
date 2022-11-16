pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/babyjub.circom";

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

  component babyPbk = BabyPbk();
  babyPbk.in <== secret;
  F_0[0] <== babyPbk.Ax;
  F_0[1] <== babyPbk.Ay;
}

component main {public [concat]} = Cassiopeia();
