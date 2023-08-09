// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "./lib/ec/alt_bn128.sol";
import "./lib/PVSSLib.sol";
import "./lib/SNARKVerifyLib.sol";
import "./lib/Instance.sol";
import "hardhat/console.sol";

struct Secret {
    address instanceVerifier;
    G1Point[] a_i;
    PVSSLib.PVSSDecryptedShare[] decryptedShares;
    bool claimed;
}

contract Cassiopeia {
    SNARKVerifier verifier;

    uint256 public n;
    uint256 public t;
    G2Point[] public pks;
    Secret[] internal secrets;

    event SharedSecret(uint256 secretID);

    constructor(uint256 _t, G2Point[] memory _pks, SNARKVerifier _verifier) {
        n = _pks.length;
        require(_t <= n, "Threshold should at most the number of participants");
        t = _t;
        for (uint256 i = 0; i < n; i++) {
            pks.push(_pks[i]);
        }
        verifier = _verifier;
    }

    function shareSecret(
        address instanceVerifier,
        PVSSLib.PVSSCiphertext memory c,
        uint256 H,
        SNARKVerifyLib.Proof memory proof
    ) public returns (uint256) {
        require(
            SNARKVerifyLib.verifyProof(
                verifier,
                H,
                c.f_i[0],
                SNARKVerifyLib.genConcat(instanceVerifier, c),
                proof
            )
        );
        PVSSLib.verifyDistribution(n, t, pks, c);

        // Add secret to storage
        Secret storage secret = secrets.push();
        secret.instanceVerifier = instanceVerifier;
        for (uint256 i = 0; i < c.a_i.length; i++) {
            secret.a_i.push(c.a_i[i]);
        }
        emit SharedSecret(secrets.length - 1);
        return secrets.length - 1;
    }

    function claim (uint256 secretID, bytes memory witness) public {
        require(InstanceVerifier(secrets[secretID].instanceVerifier).verify(witness), "Witness invalid");
        secrets[secretID].claimed = true;
    }

    function submitShare(
        uint256 secretID,
        uint256 index,
        G2Point memory decrypted
    ) public {
        require(secretID < secrets.length, "Secret does not exist");
        require(index < n, "Index out of bounds");
        require(secrets[secretID].claimed, "Not yet time to submit shares");
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
