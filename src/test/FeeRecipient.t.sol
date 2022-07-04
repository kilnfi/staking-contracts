//SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.10;

import "forge-std/Vm.sol";
import "../contracts/FeeRecipient.sol";

contract DispatcherMock {
    address internal bob = address(123);
    address internal alice = address(456);

    function dispatch(bytes32 _publicKeyRoot) external payable {
        payable(uint256(_publicKeyRoot) % 2 == 0 ? bob : alice).transfer(address(this).balance);
    }

    function getWithdrawer(bytes32 _publicKeyRoot) external view returns (address) {
        return uint256(_publicKeyRoot) % 2 == 0 ? bob : alice;
    }
}

contract FeeRecipientTest {
    Vm internal vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    FeeRecipient internal feeRecipient;
    IFeeDispatcher internal dispatcher;

    address internal bob = address(123);
    address internal alice = address(456);

    function setUp() external {
        feeRecipient = new FeeRecipient();
        dispatcher = IFeeDispatcher(address(new DispatcherMock()));
    }

    function _init(bytes32 _publicKeyRoot) internal {
        feeRecipient.init(address(dispatcher), _publicKeyRoot);
    }

    function testGetPublicKeyRoot(bytes32 _publicKeyRoot) external {
        _init(_publicKeyRoot);
        assert(feeRecipient.getPublicKeyRoot() == _publicKeyRoot);
    }

    function testGetWithdrawer(bytes32 _publicKeyRoot) external {
        _init(_publicKeyRoot);
        address receiver = uint256(_publicKeyRoot) % 2 == 0 ? bob : alice;
        assert(feeRecipient.getWithdrawer() == receiver);
    }

    function testTransferAndDispatch(uint256 _amount, bytes32 _publicKeyRoot) external {
        _init(_publicKeyRoot);
        address receiver = uint256(_publicKeyRoot) % 2 == 0 ? bob : alice;

        vm.deal(address(this), _amount);
        payable(address(feeRecipient)).transfer(_amount);

        assert(receiver.balance == 0);

        feeRecipient.withdraw();

        assert(receiver.balance == _amount);
    }

    function testSendAndDispatch(uint256 _amount, bytes32 _publicKeyRoot) external {
        _init(_publicKeyRoot);
        address receiver = uint256(_publicKeyRoot) % 2 == 0 ? bob : alice;

        vm.deal(address(this), _amount);
        assert(payable(address(feeRecipient)).send(_amount) == true);

        assert(receiver.balance == 0);

        feeRecipient.withdraw();

        assert(receiver.balance == _amount);
    }

    function testCallAndDispatch(uint256 _amount, bytes32 _publicKeyRoot) external {
        _init(_publicKeyRoot);
        address receiver = uint256(_publicKeyRoot) % 2 == 0 ? bob : alice;

        vm.deal(address(this), _amount);
        (bool status, ) = address(feeRecipient).call{value: _amount}("");
        assert(status == true);

        assert(receiver.balance == 0);

        feeRecipient.withdraw();

        assert(receiver.balance == _amount);
    }

    function testCallInexistantMethodAndDispatch(uint256 _amount, bytes32 _publicKeyRoot) external {
        _init(_publicKeyRoot);
        address receiver = uint256(_publicKeyRoot) % 2 == 0 ? bob : alice;

        vm.deal(address(this), _amount);
        (bool status, ) = address(feeRecipient).call{value: _amount}(abi.encodeWithSignature("pay()"));
        assert(status == true);

        assert(receiver.balance == 0);

        feeRecipient.withdraw();

        assert(receiver.balance == _amount);
    }
}
