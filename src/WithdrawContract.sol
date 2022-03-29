// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.10;

contract WithdrawContract {
    function getWithdrawalCredentials() external view returns (bytes32) {
        return
            bytes32(
                uint256(uint160(address(this))) + 0x0100000000000000000000000000000000000000000000000000000000000000
            );
    }
}
