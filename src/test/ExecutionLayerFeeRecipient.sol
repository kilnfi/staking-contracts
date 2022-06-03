//SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.10;

import "solmate/test/utils/DSTestPlus.sol";
import "forge-std/Vm.sol";
import "../contracts/ExecutionLayerFeeRecipient.sol";
import "../contracts/libs/BytesLib.sol";

contract StakingContractMock {
    address internal constant bob = address(1);
    address internal constant operator = address(2);

    function getWithdrawerFromPublicKeyRoot(bytes32) external pure returns (address) {
        return bob;
    }

    function getELFeeBps() external pure returns (uint256) {
        return 500;
    }

    function getCLFeeBps() external pure returns (uint256) {
        return 500;
    }

    function getELFeeTreasury(bytes32) external pure returns (address) {
        return operator;
    }

    function getCLFeeTreasury(bytes32) external pure returns (address) {
        return operator;
    }
}

contract ExecutionLayerFeeRecipientTest is DSTestPlus {
    Vm internal vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    IStakingContractFeeDetails internal stakingContract;
    ExecutionLayerFeeRecipient internal elfr;
    address internal constant bob = address(1);
    address internal constant operator = address(2);
    bytes internal constant publicKey =
        hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";

    function setUp() public {
        stakingContract = IStakingContractFeeDetails(address(new StakingContractMock()));
        elfr = new ExecutionLayerFeeRecipient(0);
        elfr.initELFR(address(stakingContract), sha256(BytesLib.pad64(publicKey)));
    }

    function testInitTwice() external {
        bytes32 pubkeyRoot = sha256(BytesLib.pad64(publicKey));
        vm.expectRevert(abi.encodeWithSignature("AlreadyInitialized()"));
        elfr.initELFR(address(stakingContract), pubkeyRoot);
    }

    function testWithdrawELFees() external {
        vm.deal(address(elfr), 1 ether);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        elfr.withdraw();
        assert(bob.balance == 0.95 ether);
        assert(operator.balance == 0.05 ether);
    }

    function testWithdrawELFeesTwice() external {
        vm.deal(address(elfr), 1 ether);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        elfr.withdraw();
        assert(bob.balance == 0.95 ether);
        assert(operator.balance == 0.05 ether);
        vm.deal(address(elfr), 1 ether);
        elfr.withdraw();
        assert(bob.balance == 1.9 ether);
        assert(operator.balance == 0.1 ether);
    }
}
