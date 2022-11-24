#!/bin/bash

ROOT=$(pwd)
NAME=cassiopeia
BUILD_DIR=$ROOT/zkp/output
PTAU_FILE=$ROOT/zkp/powersOfTau28_hez_final_14.ptau
FINAL_ZKEY=$BUILD_DIR/keys/${NAME}_final.zkey

if [ ! -d "$BUILD_DIR" ]; then
    echo "No build directory found. Creating build directory..."
    mkdir -p "$BUILD_DIR"
fi

# Build circuit
circom $ROOT/zkp/$NAME.circom --O1 --r1cs --wasm --sym --c --output "$BUILD_DIR"

mkdir -p $BUILD_DIR/keys
npx snarkjs powersoftau verify $PTAU_FILE
npx snarkjs plonk setup $BUILD_DIR/$NAME.r1cs $PTAU_FILE $FINAL_ZKEY
npx snarkjs zkey export solidityverifier $FINAL_ZKEY $ROOT/contracts/PlonkVerifier.sol
npx snarkjs zkey export verificationkey $FINAL_ZKEY $BUILD_DIR/keys/verification_key.json
