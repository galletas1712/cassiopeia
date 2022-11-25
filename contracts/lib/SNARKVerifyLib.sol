// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "./PVSSLib.sol";

interface SNARKVerifier {
    function verifyProof(
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c,
        uint[5] memory input
    ) external view returns (bool r);
}

library SNARKVerifyLib {
    struct Proof {
        G1Point a;
        G2Point b;
        G1Point c;
    }

    function genConcat(
        uint256 unlockTime,
        PVSSLib.PVSSCiphertext memory c
    ) public pure returns (uint256[2] memory concatHalves) {
        bytes32 concat = keccak256(abi.encode(unlockTime, c));
        bytes16[2] memory concatHalvesBytes = [bytes16(0), bytes16(0)];
        assembly {
            mstore(concatHalvesBytes, concat)
            mstore(add(concatHalvesBytes, 16), concat)
        }
        concatHalves[0] = uint256(
            bytes32(abi.encodePacked(bytes16(0), concatHalvesBytes[0]))
        );
        concatHalves[1] = uint256(
            bytes32(abi.encodePacked(bytes16(0), concatHalvesBytes[1]))
        );
    }

    function verifyProof(
        SNARKVerifier verifier,
        uint256 H,
        G1Point memory F_0,
        uint256[2] memory concatHalves,
        Proof memory proof
    ) public view returns (bool) {
        uint256[5] memory pubSignalsConsolidated = [
            H,
            F_0.x,
            F_0.y,
            concatHalves[0],
            concatHalves[1]
        ];
        uint256[2] memory a = [proof.a.x, proof.a.y];
        uint256[2][2] memory b = [proof.b.x, proof.b.y];
        uint256[2] memory c = [proof.c.x, proof.c.y];
        return verifier.verifyProof(a, b, c, pubSignalsConsolidated);
    }
}
