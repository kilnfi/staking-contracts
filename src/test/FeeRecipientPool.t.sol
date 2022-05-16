//SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.10;

import "solmate/test/utils/DSTestPlus.sol";
import "forge-std/Vm.sol";
import "../contracts/FeeRecipientPool.sol";
import "../contracts/interfaces/IDepositContract.sol";
import "./User.sol";

contract FeeRecipientPoolTest is DSTestPlus {
    Vm internal vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    FeeRecipientPool internal feeRecipientPool;
    UserFactory internal uf;

    address internal admin = address(1);
    address internal feeRecipient = address(2);
    bytes32 internal memberOne = bytes32(uint256(1));
    bytes32 internal memberTwo = bytes32(uint256(2));
    bytes32 internal memberThree = bytes32(uint256(3));
    address internal recipientOne = address(3);
    address internal recipientTwo = address(4);
    address internal recipientThree = address(5);

    bytes32 internal withdrawalCredentials = bytes32(uint256(4));

    function setUp() public {
        uf = new UserFactory();
        feeRecipientPool = new FeeRecipientPool(admin, feeRecipient, 10000);
    }

    function testSetFeeAsAdmin() public {
        assert(feeRecipientPool.fee() == 10000);
        vm.startPrank(admin);
        feeRecipientPool.setFee(20000);
        vm.stopPrank();
        assert(feeRecipientPool.fee() == 20000);
    }

    function testSetFeeAboveBaseAsAdmin() public {
        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSignature("InvalidFeeArgument(uint256)", 1000001));
        feeRecipientPool.setFee(1000001);
        vm.stopPrank();
    }

    function testSetFeeAsRandom(uint256 _randomSalt) public {
        address random = uf.n(_randomSalt);
        vm.startPrank(random);
        vm.expectRevert(abi.encodeWithSignature("Unauthorized(address)", random));
        feeRecipientPool.setFee(20000);
        vm.stopPrank();
    }

    function testAddMembersAsAdmin() public {
        vm.startPrank(admin);

        assert(feeRecipientPool.registered(memberOne) == false);
        feeRecipientPool.registerMember(memberOne);
        assert(feeRecipientPool.registered(memberOne) == true);

        assert(feeRecipientPool.registered(memberTwo) == false);
        feeRecipientPool.registerMember(memberTwo);
        assert(feeRecipientPool.registered(memberTwo) == true);

        assert(feeRecipientPool.registered(memberThree) == false);
        feeRecipientPool.registerMember(memberThree);
        assert(feeRecipientPool.registered(memberThree) == true);

        vm.stopPrank();
        assert(feeRecipientPool.memberCount() == 3);
    }

    function testAddMembersAsRandom(uint256 _randomSalt) public {
        address random = uf.n(_randomSalt);
        vm.startPrank(random);
        vm.expectRevert(abi.encodeWithSignature("Unauthorized(address)", random));
        feeRecipientPool.registerMember(memberOne);
        vm.stopPrank();

    }

    function testAddMembersTwiceAsAdmin() public {
        vm.startPrank(admin);

        feeRecipientPool.registerMember(memberOne);
        vm.expectRevert(abi.encodeWithSignature("AlreadyRegistered(bytes32)", memberOne));
        feeRecipientPool.registerMember(memberOne);

        vm.stopPrank();
    }

    function testRemoveMembersAsAdmin() public {
        vm.startPrank(admin);

        feeRecipientPool.registerMember(memberOne);
        feeRecipientPool.registerMember(memberTwo);
        feeRecipientPool.registerMember(memberThree);

        assert(feeRecipientPool.registered(memberOne) == true);
        feeRecipientPool.unregisterMember(memberOne);
        assert(feeRecipientPool.registered(memberOne) == false);

        assert(feeRecipientPool.registered(memberTwo) == true);
        feeRecipientPool.unregisterMember(memberTwo);
        assert(feeRecipientPool.registered(memberTwo) == false);

        assert(feeRecipientPool.registered(memberThree) == true);
        feeRecipientPool.unregisterMember(memberThree);
        assert(feeRecipientPool.registered(memberThree) == false);

        vm.stopPrank();
        assert(feeRecipientPool.memberCount() == 0);
    }

    function testRemoveMembersAsRandom(uint256 _randomSalt) public {
        address random = uf.n(_randomSalt);

        vm.startPrank(admin);
        feeRecipientPool.registerMember(memberOne);
        vm.stopPrank();

        vm.startPrank(random);
        vm.expectRevert(abi.encodeWithSignature("Unauthorized(address)", random));
        feeRecipientPool.unregisterMember(memberOne);
        vm.stopPrank();

    }

    function testRemoveInexistantMembersAsAdmin() public {
        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSignature("NotRegistered(bytes32)", memberOne));
        feeRecipientPool.unregisterMember(memberOne);

        vm.stopPrank();
    }

    function testWithdraw3EthFor3Members() public {

        vm.startPrank(admin);

        feeRecipientPool.registerMember(memberOne);
        feeRecipientPool.registerMember(memberTwo);
        feeRecipientPool.registerMember(memberThree);

        vm.deal(address(feeRecipientPool), 3 ether);

        assert(feeRecipientPool.withdrawn() == 0 ether);
        assert(address(feeRecipientPool).balance == 3 ether);
        assert(recipientOne.balance == 0);
        assert(feeRecipient.balance == 0);
        feeRecipientPool.withdraw(memberOne, recipientOne);
        assert(recipientOne.balance == 1 ether - (1 ether * 10000 / 1000000));
        assert(feeRecipient.balance == 1 ether * 10000 / 1000000);
        assert(address(feeRecipientPool).balance == 2 ether);
        assert(feeRecipientPool.withdrawn() == 1 ether);

        assert(feeRecipientPool.withdrawn() == 1 ether);
        assert(address(feeRecipientPool).balance == 2 ether);
        assert(recipientTwo.balance == 0);
        assert(feeRecipient.balance == 1 ether * 10000 / 1000000);
        feeRecipientPool.withdraw(memberTwo, recipientTwo);
        assert(recipientTwo.balance == 1 ether - (1 ether * 10000 / 1000000));
        assert(feeRecipient.balance == 2 ether * 10000 / 1000000);
        assert(address(feeRecipientPool).balance == 1 ether);
        assert(feeRecipientPool.withdrawn() == 2 ether);

        assert(feeRecipientPool.withdrawn() == 2 ether);
        assert(address(feeRecipientPool).balance == 1 ether);
        assert(recipientThree.balance == 0);
        assert(feeRecipient.balance == 2 ether * 10000 / 1000000);
        feeRecipientPool.withdraw(memberThree, recipientThree);
        assert(recipientThree.balance == 1 ether - (1 ether * 10000 / 1000000));
        assert(feeRecipient.balance == 3 ether * 10000 / 1000000);
        assert(address(feeRecipientPool).balance == 0 ether);
        assert(feeRecipientPool.withdrawn() == 3 ether);

        vm.stopPrank();

    }

    function testWithdraw9EthFor3Members() public {

        vm.startPrank(admin);

        feeRecipientPool.registerMember(memberOne);
        feeRecipientPool.registerMember(memberTwo);
        feeRecipientPool.registerMember(memberThree);

        vm.deal(address(feeRecipientPool), 3 ether);

        assert(feeRecipientPool.withdrawn() == 0 ether);
        assert(address(feeRecipientPool).balance == 3 ether);
        assert(recipientOne.balance == 0);
        assert(feeRecipient.balance == 0);
        feeRecipientPool.withdraw(memberOne, recipientOne);
        assert(recipientOne.balance == 1 ether - (1 ether * 10000 / 1000000));
        assert(feeRecipient.balance == 1 ether * 10000 / 1000000);
        assert(address(feeRecipientPool).balance == 2 ether);
        assert(feeRecipientPool.withdrawn() == 1 ether);

        assert(feeRecipientPool.withdrawn() == 1 ether);
        assert(address(feeRecipientPool).balance == 2 ether);
        assert(recipientTwo.balance == 0);
        assert(feeRecipient.balance == 1 ether * 10000 / 1000000);
        feeRecipientPool.withdraw(memberTwo, recipientTwo);
        assert(recipientTwo.balance == 1 ether - (1 ether * 10000 / 1000000));
        assert(feeRecipient.balance == 2 ether * 10000 / 1000000);
        assert(address(feeRecipientPool).balance == 1 ether);
        assert(feeRecipientPool.withdrawn() == 2 ether);

        assert(feeRecipientPool.withdrawn() == 2 ether);
        assert(address(feeRecipientPool).balance == 1 ether);
        assert(recipientThree.balance == 0);
        assert(feeRecipient.balance == 2 ether * 10000 / 1000000);
        feeRecipientPool.withdraw(memberThree, recipientThree);
        assert(recipientThree.balance == 1 ether - (1 ether * 10000 / 1000000));
        assert(feeRecipient.balance == 3 ether * 10000 / 1000000);
        assert(address(feeRecipientPool).balance == 0 ether);
        assert(feeRecipientPool.withdrawn() == 3 ether);

        vm.deal(address(feeRecipientPool), 3 ether);

        assert(feeRecipientPool.withdrawn() == 3 ether);
        assert(address(feeRecipientPool).balance == 3 ether);
        assert(recipientOne.balance == 1 ether - (1 ether * 10000 / 1000000));
        assert(feeRecipient.balance == 3 ether * 10000 / 1000000);
        feeRecipientPool.withdraw(memberOne, recipientOne);
        assert(recipientOne.balance == 2 ether - (2 ether * 10000 / 1000000));
        assert(feeRecipient.balance == 4 ether * 10000 / 1000000);
        assert(address(feeRecipientPool).balance == 2 ether);
        assert(feeRecipientPool.withdrawn() == 4 ether);

        assert(feeRecipientPool.withdrawn() == 4 ether);
        assert(address(feeRecipientPool).balance == 2 ether);
        assert(recipientTwo.balance == 1 ether - (1 ether * 10000 / 1000000));
        assert(feeRecipient.balance == 4 ether * 10000 / 1000000);
        feeRecipientPool.withdraw(memberTwo, recipientTwo);
        assert(recipientTwo.balance == 2 ether - (2 ether * 10000 / 1000000));
        assert(feeRecipient.balance == 5 ether * 10000 / 1000000);
        assert(address(feeRecipientPool).balance == 1 ether);
        assert(feeRecipientPool.withdrawn() == 5 ether);

        vm.deal(address(feeRecipientPool), 4 ether);

        assert(feeRecipientPool.withdrawn() == 5 ether);
        assert(address(feeRecipientPool).balance == 4 ether);
        assert(recipientOne.balance == 2 ether - (2 ether * 10000 / 1000000));
        assert(feeRecipient.balance == 5 ether * 10000 / 1000000);
        feeRecipientPool.withdraw(memberOne, recipientOne);
        assert(recipientOne.balance == 3 ether - (3 ether * 10000 / 1000000));
        assert(feeRecipient.balance == 6 ether * 10000 / 1000000);
        assert(address(feeRecipientPool).balance == 3 ether);
        assert(feeRecipientPool.withdrawn() == 6 ether);

        assert(feeRecipientPool.withdrawn() == 6 ether);
        assert(address(feeRecipientPool).balance == 3 ether);
        assert(recipientTwo.balance == 2 ether - (2 ether * 10000 / 1000000));
        assert(feeRecipient.balance == 6 ether * 10000 / 1000000);
        feeRecipientPool.withdraw(memberTwo, recipientTwo);
        assert(recipientTwo.balance == 3 ether - (3 ether * 10000 / 1000000));
        assert(feeRecipient.balance == 7 ether * 10000 / 1000000);
        assert(address(feeRecipientPool).balance == 2 ether);
        assert(feeRecipientPool.withdrawn() == 7 ether);

        assert(feeRecipientPool.withdrawn() == 7 ether);
        assert(address(feeRecipientPool).balance == 2 ether);
        assert(recipientThree.balance == 1 ether - (1 ether * 10000 / 1000000));
        assert(feeRecipient.balance == 7 ether * 10000 / 1000000);
        feeRecipientPool.withdraw(memberThree, recipientThree);
        assert(recipientThree.balance == 3 ether - (3 ether * 10000 / 1000000));
        assert(feeRecipient.balance == 9 ether * 10000 / 1000000);
        assert(address(feeRecipientPool).balance == 0 ether);
        assert(feeRecipientPool.withdrawn() == 9 ether);

        vm.stopPrank();

        assert(recipientOne.balance == recipientTwo.balance);
        assert(recipientOne.balance == recipientThree.balance);

    }
}
