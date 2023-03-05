// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;
import "../lib/Instance.sol";

contract SHA256PreimageVerifier is InstanceVerifier {

    bytes32 h;

    constructor (bytes32 _h) {
        h = _h;
    }

    function verify (bytes memory witness) public view override returns (bool) {
        return h == sha256(witness);
    }
}