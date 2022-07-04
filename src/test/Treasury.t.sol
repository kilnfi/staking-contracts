//SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.10;

import "forge-std/Vm.sol";
import "../contracts/Treasury.sol";

contract ContractThatCannotReceiveEth {
    receive() external payable {
        revert("no eth allowed");
    }
}

contract TreasuryTest {
    Vm internal vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    Treasury internal treasury;

    address internal admin = address(1);

    address internal bob = address(2);
    address internal alice = address(3);
    address internal claude = address(4);
    ContractThatCannotReceiveEth internal noEthPlease;

    uint256 constant BASIS_POINT = 10_000;

    function setUp() public {
        address[] memory recipients = new address[](2);
        recipients[0] = bob;
        recipients[1] = alice;
        uint256[] memory percents = new uint256[](2);
        percents[0] = BASIS_POINT / 2;
        percents[1] = BASIS_POINT / 2;
        treasury = new Treasury(admin, recipients, percents);
        noEthPlease = new ContractThatCannotReceiveEth();
    }

    function testSplitRewards() public {
        vm.deal(address(treasury), 3 ether);

        vm.startPrank(admin);
        assert(bob.balance == 0);
        assert(alice.balance == 0);
        assert(address(treasury).balance == 3 ether);

        treasury.withdraw(3 ether);

        assert(bob.balance == 1.5 ether);
        assert(alice.balance == 1.5 ether);
        assert(address(treasury).balance == 0);
        vm.stopPrank();
    }

    function testSplitInvalidAmount() public {
        vm.deal(address(treasury), 3 ether);

        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSignature("InvalidAmount()"));
        treasury.withdraw(3.1 ether);
        vm.stopPrank();
    }

    function testSplitPartialRewards() public {
        vm.deal(address(treasury), 3 ether);

        vm.startPrank(admin);
        assert(bob.balance == 0);
        assert(alice.balance == 0);
        assert(address(treasury).balance == 3 ether);

        treasury.withdraw(2 ether);

        assert(bob.balance == 1 ether);
        assert(alice.balance == 1 ether);
        assert(address(treasury).balance == 1 ether);
        vm.stopPrank();
    }

    function testReceiveWithAllMethod() public {
        vm.deal(claude, 3 ether);

        vm.startPrank(claude);
        assert(address(treasury).balance == 0);
        (bool status, ) = address(treasury).call{value: 1 ether}("");
        assert(status);
        payable(address(treasury)).transfer(1 ether);
        status = payable(address(treasury)).send(1 ether);
        assert(status);
        assert(address(treasury).balance == 3 ether);
        vm.stopPrank();

        vm.startPrank(admin);
        assert(bob.balance == 0);
        assert(alice.balance == 0);
        assert(address(treasury).balance == 3 ether);

        treasury.withdraw(3 ether);

        assert(bob.balance == 1.5 ether);
        assert(alice.balance == 1.5 ether);
        assert(address(treasury).balance == 0);
        vm.stopPrank();
    }

    function testSplitToOne() public {
        vm.deal(address(treasury), 3 ether);

        address[] memory recipients = new address[](2);
        recipients[0] = bob;
        uint256[] memory percents = new uint256[](2);
        percents[0] = BASIS_POINT;

        vm.startPrank(admin);
        treasury.setParameters(recipients, percents);
        assert(bob.balance == 0);
        assert(address(treasury).balance == 3 ether);

        treasury.withdraw(3 ether);

        assert(bob.balance == 3 ether);
        assert(address(treasury).balance == 0);
        vm.stopPrank();
    }

    function testSplitUnauthorized() public {
        vm.deal(address(treasury), 3 ether);
        vm.startPrank(bob);
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        treasury.withdraw(1 ether);
        vm.stopPrank();
    }

    function testSetParametersInvalidArrayLengths() public {
        vm.deal(address(treasury), 3 ether);
        address[] memory recipients = new address[](1);
        recipients[0] = bob;
        uint256[] memory percents = new uint256[](2);
        percents[0] = BASIS_POINT / 2;
        percents[1] = BASIS_POINT / 2;
        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSignature("InvalidArrayLengths()"));
        treasury.setParameters(recipients, percents);
        vm.stopPrank();
    }

    function testSetParametersEmptyArray() public {
        vm.deal(address(treasury), 3 ether);
        address[] memory recipients = new address[](0);
        uint256[] memory percents = new uint256[](0);
        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSignature("InvalidEmptyArray()"));
        treasury.setParameters(recipients, percents);
        vm.stopPrank();
    }

    function testSetParametersInvalidPercents() public {
        vm.deal(address(treasury), 3 ether);
        address[] memory recipients = new address[](1);
        recipients[0] = bob;
        uint256[] memory percents = new uint256[](1);
        percents[0] = BASIS_POINT + 1;
        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSignature("InvalidPercents()"));
        treasury.setParameters(recipients, percents);
        vm.stopPrank();
    }

    function testTransferError() public {
        vm.deal(address(treasury), 3 ether);
        address[] memory recipients = new address[](1);
        recipients[0] = address(noEthPlease);
        uint256[] memory percents = new uint256[](1);
        percents[0] = BASIS_POINT;
        vm.startPrank(admin);
        treasury.setParameters(recipients, percents);
        vm.expectRevert(
            abi.encodeWithSignature("TransferError(bytes)", abi.encodeWithSignature("Error(string)", "no eth allowed"))
        );
        treasury.withdraw(3 ether);
        vm.stopPrank();
    }
}
