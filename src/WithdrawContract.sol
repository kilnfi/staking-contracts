// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.10;

/// @title Ethereum Withdraw Contract
/// @author SkillZ
/// @notice This upgradeable contract will be in charge of handling the withdrawals
///         coming from the consensus layer
contract WithdrawContract {
    /// @notice Retrieve the bytes32 encoded withdrawal credentials to use for the deposits
    function getWithdrawalCredentials() external view returns (bytes32) {
        return
            bytes32(
                uint256(uint160(address(this))) + 0x0100000000000000000000000000000000000000000000000000000000000000
            );
    }
}
