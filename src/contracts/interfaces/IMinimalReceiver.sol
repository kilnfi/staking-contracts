// SPDX-License-Identifier: MIT
pragma solidity >=0.8.10;

interface IMinimalReceiver {
    function init(address _dispatcher, bytes32 _publicKeyRoot) external;

    function withdraw() external;
}
