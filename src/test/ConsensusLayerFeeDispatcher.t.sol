//SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.10;

import "forge-std/Vm.sol";
import "forge-std/Test.sol";

import "../contracts/ConsensusLayerFeeDispatcher.sol";
import "../contracts/libs/BytesLib.sol";
import "../contracts/ConsensusLayerFeeDispatcher.sol";

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

    function getMaxClPerBlock() external pure returns (uint256) {
        return 608411286029; //Based on a 5 % APY and 12 second slot duration
    }

    function getLastWithdrawFromPublicKeyRoot(bytes32) external pure returns (uint256) {
        return 1; // initial timestamp in unit test
    }
}

contract ConsensusLayerFeeDispatcherTest is Test {
    event Withdrawal(
        address indexed withdrawer,
        address indexed feeRecipient,
        bytes32 pubKeyRoot,
        uint256 rewards,
        uint256 nodeOperatorFee,
        uint256 treasuryFee
    );

    uint256 internal immutable ONE_ETH_REWARD_TIME = ((10 * 2629800) / 16) * 12;

    IStakingContractFeeDetails internal stakingContract;
    ConsensusLayerFeeDispatcher internal cld;
    address internal constant bob = address(1);
    address internal constant operator = address(2);
    address internal constant treasury = address(3);

    function setUp() public {
        stakingContract = IStakingContractFeeDetails(address(new StakingContractMock()));
        cld = new ConsensusLayerFeeDispatcher(0);
        cld.initCLD(address(stakingContract));
    }

    function testInitTwice() external {
        vm.expectRevert(abi.encodeWithSignature("AlreadyInitialized()"));
        cld.initCLD(address(stakingContract));
    }

    function testGetStakingContract() external view {
        assert(cld.getStakingContract() == address(stakingContract));
    }

    function testGetWithdrawer() external view {
        assert(cld.getWithdrawer(bytes32(0)) == bob);
        assert(cld.getWithdrawer(keccak256(bytes("another public key"))) == address(0));
    }

    function testTransferFunds() external {
        vm.deal(bob, 1 ether);
        vm.startPrank(bob);
        vm.expectRevert(abi.encodeWithSignature("InvalidCall()"));
        payable(address(cld)).transfer(1 ether);
        vm.stopPrank();
    }

    function testSendFunds() external {
        vm.deal(bob, 1 ether);
        vm.startPrank(bob);
        bool status = payable(address(cld)).send(1 ether);
        require(status == false);
        vm.stopPrank();
    }

    function testSendFundsWithCall() external {
        vm.deal(bob, 1 ether);
        vm.startPrank(bob);
        (bool status, ) = address(cld).call{value: 1 ether}("");
        require(status == false);
        vm.stopPrank();
    }

    function testFallbackError() external {
        vm.deal(bob, 1 ether);
        vm.startPrank(bob);
        (bool status, ) = address(cld).call{value: 1 ether}(abi.encodeWithSignature("thisMethodIsNotAvailable()"));
        require(status == false);
        vm.stopPrank();
    }

    function testWithdrawCLFeesExitedValidator() external {
        vm.warp(block.timestamp + ONE_ETH_REWARD_TIME);
        vm.deal(address(this), 33 ether);
        assert(bob.balance == 0);
        assert(treasury.balance == 0);
        assert(operator.balance == 0);
        vm.expectEmit(true, true, true, false); // Exact amounts not checked in the event
        emit Withdrawal(bob, operator, bytes32(0), 32.9 ether, 0.02 ether, 0.08 ether);
        cld.dispatch{value: 33 ether}(bytes32(0));

        assertApproxEqAbs(bob.balance, 32.9 ether, 10**6);
        assertApproxEqAbs(treasury.balance, 0.08 ether, 10**5);
        assertApproxEqAbs(operator.balance, 0.02 ether, 10**5);
    }

    function testWithdrawCLFeesSkimmedValidator() external {
        vm.warp(block.timestamp + ONE_ETH_REWARD_TIME * 2); //to avoid rounding errors in the event
        vm.deal(address(this), 1 ether);
        assert(bob.balance == 0);
        assert(treasury.balance == 0);
        assert(operator.balance == 0);
        vm.expectEmit(true, true, true, true);
        emit Withdrawal(bob, operator, bytes32(0), 0.9 ether, 0.02 ether, 0.08 ether);
        cld.dispatch{value: 1 ether}(bytes32(0));
        assert(bob.balance == 0.9 ether);
        assert(treasury.balance == 0.08 ether);
        assert(operator.balance == 0.02 ether);
    }

    function testWithdrawCLFeesSlashedValidator() external {
        vm.warp(block.timestamp + ONE_ETH_REWARD_TIME);
        vm.deal(address(this), 31.95 ether);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        vm.expectEmit(true, true, true, false); // ETH values in the event aren't checked
        emit Withdrawal(bob, operator, bytes32(0), 0 ether, 0 ether, 0 ether);
        cld.dispatch{value: 31.95 ether}(bytes32(0));

        assertApproxEqAbs(bob.balance, 31.85 ether, 10**6);
        assertApproxEqAbs(treasury.balance, 0.08 ether, 10**5);
        assertApproxEqAbs(operator.balance, 0.02 ether, 10**5);
    }

    function testWithdrawCLFeesTwice() external {
        vm.warp(block.timestamp + ONE_ETH_REWARD_TIME * 2); //to avoid rounding errors in the event
        vm.deal(address(this), 1 ether);
        assert(bob.balance == 0);
        assert(treasury.balance == 0);
        assert(operator.balance == 0);
        vm.expectEmit(true, true, true, true);
        emit Withdrawal(bob, operator, bytes32(0), 0.9 ether, 0.02 ether, 0.08 ether);
        cld.dispatch{value: 1 ether}(bytes32(0));
        assertApproxEqAbs(bob.balance, 0.9 ether, 10**6);
        assertApproxEqAbs(treasury.balance, 0.08 ether, 10**6);
        assertApproxEqAbs(operator.balance, 0.02 ether, 10**6);
        vm.warp(block.timestamp + ONE_ETH_REWARD_TIME);
        vm.deal(address(this), 1 ether);
        vm.expectEmit(true, true, true, true);
        emit Withdrawal(bob, operator, bytes32(0), 0.9 ether, 0.02 ether, 0.08 ether);
        cld.dispatch{value: 1 ether}(bytes32(0));
        assertApproxEqAbs(bob.balance, 1.80 ether, 10**6);
        assertApproxEqAbs(treasury.balance, 0.16 ether, 10**6);
        assertApproxEqAbs(operator.balance, 0.04 ether, 10**6);
    }

    function testWithdrawCLFeesAnotherPublicKey() external {
        vm.warp(block.timestamp + ONE_ETH_REWARD_TIME * 2); //to avoid rounding errors in the event
        vm.deal(address(this), 1 ether);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(treasury.balance == 0);
        assert(address(0).balance == 0);
        vm.expectEmit(true, true, true, true);
        emit Withdrawal(
            address(0),
            operator,
            keccak256(bytes("another public key")),
            0.9 ether,
            0.02 ether,
            0.08 ether
        );
        cld.dispatch{value: 1 ether}(keccak256(bytes("another public key")));
        assert(bob.balance == 0);
        assert(operator.balance == 0.02 ether);
        assert(treasury.balance == 0.08 ether);
        assert(address(0).balance == 0.9 ether);
    }
}
