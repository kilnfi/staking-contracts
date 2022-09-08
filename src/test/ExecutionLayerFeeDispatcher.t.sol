//SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.10;

import "forge-std/Vm.sol";
import "../contracts/ExecutionLayerFeeDispatcher.sol";
import "../contracts/libs/BytesLib.sol";
import "../contracts/ExecutionLayerFeeDispatcher.sol";

contract StakingContractMock {
    address internal constant bob = address(1);
    address internal constant operator = address(2);
    address internal constant treasury = address(3);

    function getWithdrawerFromPublicKeyRoot(bytes32 v) external pure returns (address) {
        if (v == bytes32(0)) {
            return bob;
        } else {
            return address(0);
        }
    }

    function getOperatorFee() external pure returns (uint256) {
        return 2000;
    }

    function getGlobalFee() external pure returns (uint256) {
        return 1000;
    }

    function getTreasury() external pure returns (address) {
        return treasury;
    }

    function getOperatorFeeRecipient(bytes32) external pure returns (address) {
        return operator;
    }
}

contract ExecutionLayerFeeDispatcherTest {
    event Withdrawal(
        address indexed withdrawer,
        address indexed feeRecipient,
        bytes32 pubKeyRoot,
        uint256 rewards,
        uint256 nodeOperatorFee,
        uint256 treasuryFee
    );

    Vm internal vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    IStakingContractFeeDetails internal stakingContract;
    ExecutionLayerFeeDispatcher internal eld;
    address internal constant bob = address(1);
    address internal constant operator = address(2);
    address internal constant treasury = address(3);

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
        assert(treasury.balance == 0);
        assert(operator.balance == 0);
        vm.expectEmit(true, true, true, true);
        emit Withdrawal(bob, operator, bytes32(0), 0.9 ether, 0.02 ether, 0.08 ether);
        eld.dispatch{value: 1 ether}(bytes32(0));
        assert(bob.balance == 0.9 ether);
        assert(treasury.balance == 0.08 ether);
        assert(operator.balance == 0.02 ether);
    }

    function testWithdrawELFeesTwice() external {
        vm.deal(address(this), 1 ether);
        assert(bob.balance == 0);
        assert(treasury.balance == 0);
        assert(operator.balance == 0);
        vm.expectEmit(true, true, true, true);
        emit Withdrawal(bob, operator, bytes32(0), 0.9 ether, 0.02 ether, 0.08 ether);
        eld.dispatch{value: 1 ether}(bytes32(0));
        assert(bob.balance == 0.9 ether);
        assert(treasury.balance == 0.08 ether);
        assert(operator.balance == 0.02 ether);
        vm.deal(address(this), 1 ether);
        vm.expectEmit(true, true, true, true);
        emit Withdrawal(bob, operator, bytes32(0), 0.9 ether, 0.02 ether, 0.08 ether);
        eld.dispatch{value: 1 ether}(bytes32(0));
        assert(bob.balance == 1.8 ether);
        assert(treasury.balance == 0.16 ether);
        assert(operator.balance == 0.04 ether);
    }

    function testWithdrawELAnotherPublicKey() external {
        vm.deal(address(this), 1 ether);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(treasury.balance == 0);
        assert(address(0).balance == 0);
        vm.expectEmit(true, true, true, true);
        emit Withdrawal(
            address(0),
            operator,
            bytes32(keccak256(bytes("another public key"))),
            0.9 ether,
            0.02 ether,
            0.08 ether
        );
        eld.dispatch{value: 1 ether}(bytes32(keccak256(bytes("another public key"))));
        assert(bob.balance == 0);
        assert(operator.balance == 0.02 ether);
        assert(treasury.balance == 0.08 ether);
        assert(address(0).balance == 0.9 ether);
    }
}
