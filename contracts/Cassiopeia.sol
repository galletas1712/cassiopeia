// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "./lib/ec/alt_bn128.sol";
import "./lib/PVSSLib.sol";
import "./lib/SNARKVerifyLib.sol";
import "hardhat/console.sol";

struct Secret {
    uint256 unlockTime;
    G1Point[] a_i;
    PVSSLib.PVSSDecryptedShare[] decryptedShares;
    uint256 value;
    mapping(address => bool) shareSubmitted;
    uint256 countSharesSubmitted;
    mapping(address => bool) collateralDeposited;
    uint256 insuranceValue;
    bool insurancePaid;
    address dealer;
}

contract Cassiopeia {
    uint256 constant GRACE_PERIOD = 100; // in number of blocks
    // maximum risk free rate for any period of time across all committee members
    uint256 constant RISK_FREE_RATE = 23; // per block, 0.0023%

    SNARKVerifier verifier;

    uint256 public n;
    uint256 public t;
    G2Point[] internal pks; // TODO: map committee member Ethereum addresses to pks
    Secret[] internal secrets;
    mapping(address => uint256) committeeBalances;
    uint256 liabilities;

    event SharedSecret(uint256 secretID);

    function topUp() payable {
        committeeBalances[msg.sender] += msg.value;
    }

    constructor(uint256 _t, G2Point[] memory _pks, SNARKVerifier _verifier) {
        n = _pks.length;
        require(_t <= n, "Threshold should at most the number of participants");
        t = _t;
        for (uint256 i = 0; i < n; i++) {
            pks.push(_pks[i]);
        }
        verifier = _verifier;
    }

    // TODO: make this support witness encryption
    function shareSecret(
        uint256 unlockTime,
        PVSSLib.PVSSCiphertext memory c,
        uint256 H,
        SNARKVerifyLib.Proof memory proof,
        uint256 insuranceValue
    ) public payable returns (uint256) {
        // rationality requirement for committee members
        require(
            // TODO: clean up the math here
            (n - t + 1) * msg.value > n * insuranceValue * ((1 + r/10000)**unlockTime - 1)
            // easier version:
            // (n - t + 1) * msg.value > n * insuranceValue * ((1 + r)*unlockTime - 1)
        );
        require(
            this.balance >= 
        );
        require(
            SNARKVerifyLib.verifyProof(
                verifier,
                H,
                c.f_i[0],
                SNARKVerifyLib.genConcat(unlockTime, c),
                proof
            )
        );
        PVSSLib.verifyDistribution(n, t, pks, c);

        // Add secret to storage
        Secret storage secret = secrets.push();
        secret.dealer = msg.sender;
        secret.unlockTime = unlockTime;
        for (uint256 i = 0; i < c.a_i.length; i++) {
            secret.a_i.push(c.a_i[i]);
        }
        emit SharedSecret(secrets.length - 1);
        return secrets.length - 1;
    }
    
    // TODO: turn 3 period checks (before unlock, during grace period, after grace period) into modifiers

    function submitShare(
        uint256 secretID,
        uint256 index,
        G2Point memory decrypted
    ) public inGracePeriod(secretID) {
        require(secretID < secrets.length, "Secret does not exist");
        require(index < n, "Index out of bounds");
        require(!secret[secretID].sharedSubmitted[index]);

        PVSSLib.verifyShare(secrets[secretID].a_i[index], decrypted);

        secrets[secretID].decryptedShares.push(
            PVSSLib.PVSSDecryptedShare(index, decrypted)
        );

        secret[secretID].sharesSubmitted[index] = true;
        ++secret[secretID].countSharesSubmitted;
    }

    modifier beforeUnlock(uint256 secretID) {
        require(block.number < secret[secretID].unlockTime);
        _;
    }

    modifier inGracePeriod(uint256 secretID) {
        require(block.number >= secret[secretID].unlockTime);
        require(block.number < secret[secretID].unlockTime + GRACE_PERIOD);
        _;
    }

    modifier afterGracePeriod(uint256 secretID) {
        require(block.number >= secret[secretID].unlockTime + GRACE_PERIOD);
        _;
    }

    function reclaimMemberCollateral(uint256 secretID) afterGracePeriod(secretID) {
    }

    function reclaimDealerCollateral(uint256 secretID) afterGracePeriod(secretID) {
        require(!secret[secretID].insurancePaid);
        secret[secretID].insurancePaid = true;

        uint256 amount;

        if (secret[secretID].countSharesSubmitted >= t) {
            // happy path

        }
        else {

        }

        secret[secretID].dealer.send(amount);
    }

    function getPK(uint256 i) public view returns (G2Point memory) {
        return pks[i];
    }

    function getSecret(uint256 secretID) public view returns (Secret memory) {
        return secrets[secretID];
    }
}
