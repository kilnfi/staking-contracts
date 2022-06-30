//SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.10;

import "forge-std/Vm.sol";
import "../contracts/libs/BytesLib.sol";
import "../contracts/ConsensusLayerFeeRecipient.sol";

contract StakingContractMock {
    address internal constant bob = address(1);
    address internal constant operator = address(2);
    address internal constant treasury = address(3);

    function getWithdrawerFromPublicKeyRoot(bytes32) external pure returns (address) {
        return bob;
    }

    function getELFee() external pure returns (uint256) {
        return 200;
    }

    function getCLFee() external pure returns (uint256) {
        return 200;
    }

    function getTreasuryFee() external pure returns (uint256) {
        return 800;
    }

    function getTreasury() external pure returns (address) {
        return treasury;
    }

    function getOperatorFeeRecipient(bytes32) external pure returns (address) {
        return operator;
    }
}

contract ConsensusLayerFeeRecipientTest {
    event Withdrawal(
        address indexed withdrawer,
        address indexed feeRecipient,
        uint256 rewards,
        uint256 fee,
        uint256 treasuryFee
    );

    Vm internal vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    IStakingContractFeeDetails internal stakingContract;
    ConsensusLayerFeeRecipient internal clfr;
    address internal constant bob = address(1);
    address internal constant operator = address(2);
    address internal constant treasury = address(3);
    bytes internal constant publicKey =
        hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";

    function setUp() public {
        stakingContract = IStakingContractFeeDetails(address(new StakingContractMock()));
        clfr = new ConsensusLayerFeeRecipient(0);
        clfr.initCLFR(address(stakingContract), sha256(BytesLib.pad64(publicKey)));
    }

    function testInitTwice() external {
        bytes32 pubkeyRoot = sha256(BytesLib.pad64(publicKey));
        vm.expectRevert(abi.encodeWithSignature("AlreadyInitialized()"));
        clfr.initCLFR(address(stakingContract), pubkeyRoot);
    }

    function testGetStakingContract() external view {
        assert(clfr.getStakingContract() == address(stakingContract));
    }

    function testGetWithdrawer() external view {
        assert(clfr.getWithdrawer() == bob);
    }

    function testGetPubKeyRoot() external view {
        assert(clfr.getPublicKeyRoot() == sha256(BytesLib.pad64(publicKey)));
    }

    function testTransferFunds() external {
        vm.deal(bob, 1 ether);
        vm.startPrank(bob);
        payable(address(clfr)).transfer(1 ether);
        vm.stopPrank();
    }

    function testSendFunds() external {
        vm.deal(bob, 1 ether);
        vm.startPrank(bob);
        bool status = payable(address(clfr)).send(1 ether);
        require(status == true);
        vm.stopPrank();
    }

    function testSendFundsWithCall() external {
        vm.deal(bob, 1 ether);
        vm.startPrank(bob);
        (bool status, ) = address(clfr).call{value: 1 ether}("");
        require(status == true);
        vm.stopPrank();
    }

    function testFallbackError() external {
        vm.deal(bob, 1 ether);
        vm.startPrank(bob);
        (bool status, ) = address(clfr).call{value: 1 ether}(abi.encodeWithSignature("thisMethodIsNotAvailable()"));
        require(status == false);
        vm.stopPrank();
    }

    function testWithdrawExistingFunds() external {
        ConsensusLayerFeeRecipient futureRecipientAddress = ConsensusLayerFeeRecipient(payable(address(12345)));
        vm.deal(address(futureRecipientAddress), 33 ether);
        vm.etch(address(futureRecipientAddress), address(clfr).code);
        futureRecipientAddress.initCLFR(address(stakingContract), sha256(BytesLib.pad64(publicKey)));

        assert(bob.balance == 0);
        assert(operator.balance == 0);
        vm.expectEmit(true, true, true, true);
        emit Withdrawal(bob, operator, 32.9 ether, 0.02 ether, 0.08 ether);
        futureRecipientAddress.withdraw();
        assert(bob.balance == 32.9 ether);
        assert(operator.balance == 0.02 ether);
        assert(treasury.balance == 0.08 ether);
    }

    function testWithdrawCLFeesExitedValidator() external {
        vm.deal(address(clfr), 33 ether);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        vm.expectEmit(true, true, true, true);
        emit Withdrawal(bob, operator, 32.9 ether, 0.02 ether, 0.08 ether);
        clfr.withdraw();
        assert(bob.balance == 32.9 ether);
        assert(operator.balance == 0.02 ether);
        assert(treasury.balance == 0.08 ether);
    }

    function testWithdrawCLFeesSkimmedValidator() external {
        vm.deal(address(clfr), 1 ether);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        vm.expectEmit(true, true, true, true);
        emit Withdrawal(bob, operator, 0.9 ether, 0.02 ether, 0.08 ether);
        clfr.withdraw();
        assert(bob.balance == 0.9 ether);
        assert(operator.balance == 0.02 ether);
        assert(treasury.balance == 0.08 ether);
    }

    function testWithdrawCLFeesSlashedValidator() external {
        vm.deal(address(clfr), 31.95 ether);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        vm.expectEmit(true, true, true, true);
        emit Withdrawal(bob, operator, 31.95 ether, 0 ether, 0 ether);
        clfr.withdraw();
        assert(bob.balance == 31.95 ether);
        assert(operator.balance == 0 ether);
        assert(treasury.balance == 0 ether);
    }

    function testWithdrawCLFeesTwice() external {
        vm.deal(address(clfr), 1 ether);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        vm.expectEmit(true, true, true, true);
        emit Withdrawal(bob, operator, 0.90 ether, 0.02 ether, 0.08 ether);
        clfr.withdraw();
        assert(bob.balance == 0.90 ether);
        assert(operator.balance == 0.02 ether);
        assert(treasury.balance == 0.08 ether);
        vm.deal(address(clfr), 1 ether);
        vm.expectEmit(true, true, true, true);
        emit Withdrawal(bob, operator, 0.90 ether, 0.02 ether, 0.08 ether);
        clfr.withdraw();
        assert(bob.balance == 1.8 ether);
        assert(operator.balance == 0.04 ether);
        assert(treasury.balance == 0.16 ether);
    }
}
