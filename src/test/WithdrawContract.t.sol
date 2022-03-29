//SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.10;

import "solmate/test/utils/DSTestPlus.sol";
import "forge-std/Vm.sol";

import "../WithdrawContract.sol";

contract WithdrawContractTest is DSTestPlus {
    Vm internal vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    WithdrawContract withdraw;

    function setUp() public {
        withdraw = new WithdrawContract();
    }

    function testWithdrawalCredentials() public view {
        assert(
            withdraw.getWithdrawalCredentials() ==
                bytes32(
                    uint256(uint160(address(withdraw))) +
                        0x0100000000000000000000000000000000000000000000000000000000000000
                )
        );
    }
}
