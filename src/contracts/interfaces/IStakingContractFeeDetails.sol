// SPDX-License-Identifier: MIT
pragma solidity >=0.8.10;

interface IStakingContractFeeDetails {
    function getWithdrawerFromPublicKeyRoot(bytes32 _publicKeyRoot) external view returns (address);

    function getELFeeBps() external view returns (uint256);

    function getCLFeeBps() external view returns (uint256);

    function getELFeeTreasury(bytes32 pubKeyRoot) external view returns (address);

    function getCLFeeTreasury(bytes32 pubKeyRoot) external view returns (address);
}
