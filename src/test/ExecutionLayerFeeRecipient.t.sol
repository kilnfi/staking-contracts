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

    function getELFee() external pure returns (uint256) {
        return 500;
    }

    function getCLFee() external pure returns (uint256) {
        return 500;
    }

    function getFeeTreasury(bytes32) external pure returns (address) {
        return operator;
    }
}

contract ExecutionLayerFeeRecipientTest is DSTestPlus {
    event Withdrawal(address indexed withdrawer, address indexed feeRecipient, uint256 rewards, uint256 fee);

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

    function testGetStakingContract() external view {
        assert(elfr.getStakingContract() == address(stakingContract));
    }

    function testGetWithdrawer() external view {
        assert(elfr.getWithdrawer() == bob);
    }

    function testGetPubKeyRoot() external view {
        assert(elfr.getPublicKeyRoot() == sha256(BytesLib.pad64(publicKey)));
    }

    function testTransferFunds() external {
        vm.deal(bob, 1 ether);
        vm.startPrank(bob);
        payable(address(elfr)).transfer(1 ether);
        vm.stopPrank();
    }

    function testSendFunds() external {
        vm.deal(bob, 1 ether);
        vm.startPrank(bob);
        bool status = payable(address(elfr)).send(1 ether);
        require(status == true);
        vm.stopPrank();
    }

    function testSendFundsWithCall() external {
        vm.deal(bob, 1 ether);
        vm.startPrank(bob);
        (bool status, ) = address(elfr).call{value: 1 ether}("");
        require(status == true);
        vm.stopPrank();
    }

    function testFallbackError() external {
        vm.deal(bob, 1 ether);
        vm.startPrank(bob);
        (bool status, ) = address(elfr).call{value: 1 ether}(abi.encodeWithSignature("thisMethodIsNotAvailable()"));
        require(status == false);
        vm.stopPrank();
    }

    function testWithdrawExistingFunds() external {
        ExecutionLayerFeeRecipient futureRecipientAddress = ExecutionLayerFeeRecipient(payable(address(12345)));
        vm.deal(address(futureRecipientAddress), 1 ether);
        vm.etch(address(futureRecipientAddress), address(elfr).code);
        futureRecipientAddress.initELFR(address(stakingContract), sha256(BytesLib.pad64(publicKey)));

        assert(bob.balance == 0);
        assert(operator.balance == 0);
        vm.expectEmit(true, true, true, true);
        emit Withdrawal(bob, operator, 0.95 ether, 0.05 ether);
        futureRecipientAddress.withdraw();
        assert(bob.balance == 0.95 ether);
        assert(operator.balance == 0.05 ether);
    }

    function testWithdrawELFees() external {
        vm.deal(address(elfr), 1 ether);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        vm.expectEmit(true, true, true, true);
        emit Withdrawal(bob, operator, 0.95 ether, 0.05 ether);
        elfr.withdraw();
        assert(bob.balance == 0.95 ether);
        assert(operator.balance == 0.05 ether);
    }

    function testWithdrawELFeesTwice() external {
        vm.deal(address(elfr), 1 ether);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        vm.expectEmit(true, true, true, true);
        emit Withdrawal(bob, operator, 0.95 ether, 0.05 ether);
        elfr.withdraw();
        assert(bob.balance == 0.95 ether);
        assert(operator.balance == 0.05 ether);
        vm.deal(address(elfr), 1 ether);
        vm.expectEmit(true, true, true, true);
        emit Withdrawal(bob, operator, 0.95 ether, 0.05 ether);
        elfr.withdraw();
        assert(bob.balance == 1.9 ether);
        assert(operator.balance == 0.1 ether);
    }
}
