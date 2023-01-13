#!/bin/bash

ROOT=$(pwd)
NAME=cassiopeia
BUILD_DIR=$ROOT/zkp/output
PTAU_FILE=$ROOT/zkp/powersOfTau28_hez_final_23.ptau
FINAL_ZKEY=$BUILD_DIR/keys/${NAME}_final.zkey

if [ ! -d "$BUILD_DIR" ]; then
    echo "No build directory found. Creating build directory..."
    mkdir -p "$BUILD_DIR"
fi

# Build circuit
circom $ROOT/zkp/$NAME.circom --O1 --c --output "$BUILD_DIR"
cd $BUILD_DIR/cassiopeia_cpp
make
cd $ROOT

mkdir -p $BUILD_DIR/keys
npx snarkjs groth16 setup $BUILD_DIR/$NAME.r1cs $PTAU_FILE /tmp/cassiopeia_0.zkey
npx snarkjs zkey contribute /tmp/cassiopeia_0.zkey $FINAL_ZKEY -v -e="Some random entropy"
npx snarkjs zkey export solidityverifier $FINAL_ZKEY $ROOT/contracts/SNARKVerifier.sol
npx snarkjs zkey export verificationkey $FINAL_ZKEY $BUILD_DIR/keys/verification_key.json

