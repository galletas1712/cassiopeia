// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;
import "../lib/Instance.sol";

contract TimelockVerifier is InstanceVerifier {

    uint256 public unlockTime;

    constructor (uint256 _unlockTime) {
        unlockTime = _unlockTime;
    }

    function verify (bytes memory witness) public view override returns (bool) {
        return block.number >= unlockTime;
    }
}