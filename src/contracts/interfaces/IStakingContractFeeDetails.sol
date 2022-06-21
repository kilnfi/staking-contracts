// SPDX-License-Identifier: MIT
pragma solidity >=0.8.10;

interface IStakingContractFeeDetails {
    function getWithdrawerFromPublicKeyRoot(bytes32 _publicKeyRoot) external view returns (address);

    function getELFee() external view returns (uint256);

    function getCLFee() external view returns (uint256);

    function getOperatorFeeRecipient(bytes32 pubKeyRoot) external view returns (address);
}
