// SPDX-License-Identifier: MIT
pragma solidity >=0.8.10;

interface IELFeeRecipient {
    function initELFR(address _stakingContract, bytes32 _publicKeyRoot) external;

    function withdraw() external;
}

interface ICLFeeRecipient {
    function initCLFR(address _stakingContract, bytes32 _publicKeyRoot) external;

    function withdraw() external;
}
