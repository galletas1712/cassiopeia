// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "./lib/ec/alt_bn128.sol";
import "./lib/PVSSLib.sol";
import "./lib/SNARKVerifyLib.sol";
import "./PlonkVerifier.sol";
import "hardhat/console.sol";

struct Secret {
    uint256 unlockTime;
    G1Point[] a_i;
    PVSSLib.PVSSDecryptedShare[] decryptedShares;
}

contract Cassiopeia {
    PlonkVerifier verifier;

    uint256 public n;
    uint256 public t;
    G2Point[] internal pks;
    Secret[] internal secrets;

    event SharedSecret(uint256 secretID);

    constructor(
        uint256 _t,
        G2Point[] memory _pks,
        PlonkVerifier _verifier
    ) {
        n = _pks.length;
        require(_t <= n, "Threshold should at most the number of participants");
        t = _t;
        for (uint256 i = 0; i < n; i++) {
            pks.push(_pks[i]);
        }
        verifier = _verifier;
    }

    function shareSecret(
        uint256 unlockTime,
        PVSSLib.PVSSCiphertext memory c,
        SNARKVerifyLib.CircuitPublicSignals memory pubSignals,
        bytes memory proof
    ) public returns (uint256) {
        require(
            SNARKVerifyLib.verifyProof(
                verifier,
                SNARKVerifyLib.genConcat(unlockTime, c),
                pubSignals,
                proof
            )
        );
        // TODO: Chaum Pedersen
        PVSSLib.verifyDistribution(n, t, pks, c);

        // Add secret to storage
        Secret storage secret = secrets.push();
        secret.unlockTime = unlockTime;
        for (uint256 i = 0; i < c.a_i.length; i++) {
            secret.a_i.push(c.a_i[i]);
        }
        emit SharedSecret(secrets.length - 1);
        return secrets.length - 1;
    }

    function submitShare(
        uint256 secretID,
        uint256 index,
        G2Point memory decrypted
    ) public {
        require(secretID < secrets.length, "Secret does not exist");
        require(index < n, "Index out of bounds");
        require(block.timestamp >= secrets[secretID].unlockTime);
        PVSSLib.verifyShare(secrets[secretID].a_i[index], decrypted);

        secrets[secretID].decryptedShares.push(
            PVSSLib.PVSSDecryptedShare(index, decrypted)
        );
    }

    function getPK(uint256 i) public view returns (G2Point memory) {
        return pks[i];
    }

    function getSecret(uint256 secretID) public view returns (Secret memory) {
        return secrets[secretID];
    }
}
