//SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.10;

import "solmate/test/utils/DSTestPlus.sol";
import "forge-std/Vm.sol";
import "../contracts/ExecutionLayerFeeDispatcher.sol";
import "../contracts/libs/BytesLib.sol";

contract StakingContractMock {
    address internal constant bob = address(1);
    address internal constant operator = address(2);

    function getWithdrawerFromPublicKeyRoot(bytes32 v) external pure returns (address) {
        if (v == bytes32(0)) {
            return bob;
        } else {
            return address(0);
        }
    }

    function getELFee() external pure returns (uint256) {
        return 500;
    }

    function getCLFee() external pure returns (uint256) {
        return 500;
    }

    function getOperatorFeeRecipient(bytes32) external pure returns (address) {
        return operator;
    }
}

contract ExecutionLayerFeeRecipientTest is DSTestPlus {
    event Withdrawal(address indexed withdrawer, address indexed feeRecipient, uint256 rewards, uint256 fee);

    Vm internal vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    IStakingContractFeeDetails internal stakingContract;
    ExecutionLayerFeeDispatcher internal eld;
    address internal constant bob = address(1);
    address internal constant operator = address(2);

    function setUp() public {
        stakingContract = IStakingContractFeeDetails(address(new StakingContractMock()));
        eld = new ExecutionLayerFeeDispatcher(0);
        eld.initELD(address(stakingContract));
    }

    function testInitTwice() external {
        vm.expectRevert(abi.encodeWithSignature("AlreadyInitialized()"));
        eld.initELD(address(stakingContract));
    }

    function testGetStakingContract() external view {
        assert(eld.getStakingContract() == address(stakingContract));
    }

    function testGetWithdrawer() external view {
        assert(eld.getWithdrawer(bytes32(0)) == bob);
        assert(eld.getWithdrawer(keccak256(bytes("another public key"))) == address(0));
    }

    function testTransferFunds() external {
        vm.deal(bob, 1 ether);
        vm.startPrank(bob);
        vm.expectRevert(abi.encodeWithSignature("InvalidCall()"));
        payable(address(eld)).transfer(1 ether);
        vm.stopPrank();
    }

    function testSendFunds() external {
        vm.deal(bob, 1 ether);
        vm.startPrank(bob);
        bool status = payable(address(eld)).send(1 ether);
        require(status == false);
        vm.stopPrank();
    }

    function testSendFundsWithCall() external {
        vm.deal(bob, 1 ether);
        vm.startPrank(bob);
        (bool status, ) = address(eld).call{value: 1 ether}("");
        require(status == false);
        vm.stopPrank();
    }

    function testFallbackError() external {
        vm.deal(bob, 1 ether);
        vm.startPrank(bob);
        (bool status, ) = address(eld).call{value: 1 ether}(abi.encodeWithSignature("thisMethodIsNotAvailable()"));
        require(status == false);
        vm.stopPrank();
    }

    function testWithdrawELFees() external {
        vm.deal(address(this), 1 ether);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        vm.expectEmit(true, true, true, true);
        emit Withdrawal(bob, operator, 0.95 ether, 0.05 ether);
        eld.dispatch{value: 1 ether}(bytes32(0));
        assert(bob.balance == 0.95 ether);
        assert(operator.balance == 0.05 ether);
    }

    function testWithdrawELFeesTwice() external {
        vm.deal(address(this), 1 ether);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        vm.expectEmit(true, true, true, true);
        emit Withdrawal(bob, operator, 0.95 ether, 0.05 ether);
        eld.dispatch{value: 1 ether}(bytes32(0));
        assert(bob.balance == 0.95 ether);
        assert(operator.balance == 0.05 ether);
        vm.deal(address(this), 1 ether);
        vm.expectEmit(true, true, true, true);
        emit Withdrawal(bob, operator, 0.95 ether, 0.05 ether);
        eld.dispatch{value: 1 ether}(bytes32(0));
        assert(bob.balance == 1.9 ether);
        assert(operator.balance == 0.1 ether);
    }

    function testWithdrawELAnotherPublicKey() external {
        vm.deal(address(this), 1 ether);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(address(0).balance == 0);
        vm.expectEmit(true, true, true, true);
        emit Withdrawal(address(0), operator, 0.95 ether, 0.05 ether);
        eld.dispatch{value: 1 ether}(bytes32(keccak256(bytes("another public key"))));
        assert(bob.balance == 0);
        assert(operator.balance == 0.05 ether);
        assert(address(0).balance == 0.95 ether);
    }
}
