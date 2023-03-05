// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

abstract contract InstanceVerifier {
    function verify (bytes memory witness) virtual public returns (bool);
}