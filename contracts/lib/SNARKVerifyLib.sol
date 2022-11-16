// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "./PVSSLib.sol";
import "../PlonkVerifier.sol";

library SNARKVerifyLib {
    struct CircuitPublicSignals {
        uint256 hashCmt;
        uint256[2] babyJubCmt;
    }

    function genConcat(uint256 unlockTime, PVSSLib.PVSSCiphertext memory c)
        public
        pure
        returns (uint256[2] memory concatHalves)
    {
        bytes32 concat = keccak256(abi.encode(unlockTime, c));
        bytes16[2] memory concatHalvesBytes = [bytes16(0), bytes16(0)];
        assembly {
            mstore(concatHalvesBytes, concat)
            mstore(add(concatHalvesBytes, 16), concat)
        }
        concatHalves[0] = uint256(bytes32(abi.encodePacked(bytes16(0), concatHalvesBytes[0])));
        concatHalves[1] = uint256(bytes32(abi.encodePacked(bytes16(0), concatHalvesBytes[1])));
    }

    function verifyProof(
        PlonkVerifier verifier,
        uint256[2] memory concatHalves,
        CircuitPublicSignals memory pubSignals,
        bytes memory proof
    ) public view returns (bool) {
        uint256[] memory pubSignalsConsolidated = new uint256[](5);
        pubSignalsConsolidated[0] = pubSignals.hashCmt;
        pubSignalsConsolidated[1] = pubSignals.babyJubCmt[0];
        pubSignalsConsolidated[2] = pubSignals.babyJubCmt[1];
        pubSignalsConsolidated[3] = concatHalves[0];
        pubSignalsConsolidated[4] = concatHalves[1];
        return verifier.verifyProof(proof, pubSignalsConsolidated);
    }
}
