// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.10;

import "solmate/test/utils/DSTestPlus.sol";
import "forge-std/Vm.sol";
import "../StakingContract.sol";
import "../interfaces/IDepositContract.sol";

contract DepositContractMock is IDepositContract {
    event DepositEvent(bytes pubkey, bytes withdrawal_credentials, bytes amount, bytes signature, bytes index);

    uint256 internal counter;

    function to_little_endian_64(uint64 value) internal pure returns (bytes memory ret) {
        ret = new bytes(8);
        bytes8 bytesValue = bytes8(value);
        // Byteswapping during copying to bytes.
        ret[0] = bytesValue[7];
        ret[1] = bytesValue[6];
        ret[2] = bytesValue[5];
        ret[3] = bytesValue[4];
        ret[4] = bytesValue[3];
        ret[5] = bytesValue[2];
        ret[6] = bytesValue[1];
        ret[7] = bytesValue[0];
    }

    function deposit(
        bytes calldata pubkey,
        bytes calldata withdrawalCredentials,
        bytes calldata signature,
        bytes32
    ) external payable {
        emit DepositEvent(
            pubkey,
            withdrawalCredentials,
            to_little_endian_64(uint64(msg.value / 1 gwei)),
            signature,
            to_little_endian_64(uint64(counter))
        );
        counter += 1;
    }
}

contract StakingContractTest is DSTestPlus {
    Vm internal vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    StakingContract internal stakingContract;
    DepositContractMock internal depositContract;

    address internal admin = address(1);
    address internal bob = address(2);
    address internal alice = address(3);

    bytes32 internal withdrawalCredentials = bytes32(uint256(4));

    function setUp() public {
        stakingContract = new StakingContract();
        depositContract = new DepositContractMock();
        stakingContract.initialize_1(admin, 0.1 ether, address(depositContract), withdrawalCredentials);

        bytes[] memory publicKeys = new bytes[](10);
        publicKeys[
            0
        ] = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        publicKeys[
            1
        ] = hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060";
        publicKeys[
            2
        ] = hex"14451b3fb9288549aff6dea9843b43e0c47a3b856f307732175230e254c0004e48b02414987088ac7003e148930017b4";
        publicKeys[
            3
        ] = hex"9a1a8d4600f33d463c4afc07bbfc82703c9fcf81a5891f90a71c86a02faff443c6c3b2592bd44d5d3d7a93cb4aaaa105";
        publicKeys[
            4
        ] = hex"612496d61e68140a5418b468f872bf2f3e79f9cb0d9c3e889663fca02939b31e8ee3092203ee1417128e965c6406a07f";
        publicKeys[
            5
        ] = hex"68abf2ebe2689cf6c853ef126ffa8574c2a7d913e28de9147fa6b96706ea5bf9eacd1aba06edeaee155009fb912c0007";
        publicKeys[
            6
        ] = hex"0774cc64136fcffde12ed731260bc5529df64da298f493561198e9d6acf42cf21e853ae7b2df85f27d2183149969d623";
        publicKeys[
            7
        ] = hex"b9237254c2cfe1d0082742eb042ac096d686dbe03c79ee31cbd03bb4682f8797043eed9f6e622814831ac5dfe1176552";
        publicKeys[
            8
        ] = hex"fb7f9b6ff38a149ae1d8414097a32fd96da6453c52fda13e3402a09e2fa6886daa4300f09c73e4bc2901b99c44744c5c";
        publicKeys[
            9
        ] = hex"fdca2994adc49ddccb195bda2510e50a4ae10de26cf96dee5e577689f51650a610a33da0a826ae47247d8d1189cb3386";

        bytes[] memory signatures = new bytes[](10);
        signatures[
            0
        ] = hex"ccb81f4485957f440bc17dbe760f374cbb112c6f12fa10e8709fac4522b30440d918c7bb867fa04f6b3cfbd977455f8f2fde586fdf3d7baa429e98e497ff871f3b8db1528b2b964fa24d26e377c74746496cc719c50dbf391fb3f74f5ca4b93a";
        signatures[
            1
        ] = hex"02a9f0007cd7b7d2af2d1b07c8600ab86a5d27dc51a29c2e3007c7a69cb73bcaecc764641e02370955dba100428d259d6475ee3566872bd43b0e73e55b9669e50f2b1666e57b326a5dfad655c7921e0dfb421b1ec59c8fdb48eb77421fd06966";
        signatures[
            2
        ] = hex"f393d619cbf13ff427df11dcb17026df25f35268de5b168e359c16f2a3d5fbc6376db44638d773c851c875f21222448433d285920e8bdc4f5cbff130d7387c0a9589324286aea398e5aacad3bbfe3992dfce62571f0e282ed9c29e3fa5b07aa5";
        signatures[
            3
        ] = hex"c81749589b1170d3b85a84331e2f6b8e26eadebfd569b225759f40bbd12d6c3d253ed3f379b014b2ea44cce54d362072e2d020ff139a903b7d87fc3fddc2e6657c83e0b79851c22c6e0e477463463c97d6cc0e2e2de5e35b227bddb285521be3";
        signatures[
            4
        ] = hex"766358abaf3159d89f68c9770e28278f177088cfc4089b817effaaecabdffa4e66427868b105cb9348ea2d84eeea059a5d1ff3277d6f9cf656fc973d07cabed70fb8f8eb2798a65d207a8e1f8a26910949db9fa62d62bc15ecc097a93a27a187";
        signatures[
            5
        ] = hex"3405b8589a4ddf0ecf0303c6031484562b32eb7881975026524d6d4a9de6cd73fe2c324501586b9b6fa6bce950bbd21472278302f83dbfd6be036f2fc36d299d66578e844be3d6aa8314fab468f038fd6e130ada0a886fccfb2fd843f7dd07e8";
        signatures[
            6
        ] = hex"968401bbe2af7345fce52ba4b310b30af2d54b15669d06c206682c1730ab6b17787e361f04401f78dc5cbd5fac955df4e83c24cdabfabdb3f4ea40961d04a5ca166c17694fca144025b47131a68ddb230d36fe6e831e82624c9a925d706bff86";
        signatures[
            7
        ] = hex"982852b26ebf019a3f6ee36aedbbc6bec2d50531a233e09225493d3c5fd48379aec373baf622fb9feed6261e5296e5ae6601e7523c7f386801ed63a344b07106a0d03e5848209db5e114c0e67884916a43a1bfb77d9b8ea113c3ba8cad4b006a";
        signatures[
            8
        ] = hex"afeadcc31e70e85c5efecaf807154d011c1413340d4b592d2f270fb48b2050e08493c1427ddfac8dcc27fe434d32a35dcbddbcb1c4e22ead6734a4ac910f6768bc9ff6b355c1151695e41121cdcc9d9d3b18cf4d66ca3c1db0527c471a0dcf25";
        signatures[
            9
        ] = hex"6590602a7269dcb26175e7eb370bd9794ac8ab558bea69e6a92d8e818b675a80e2df0516b8307291d93cb85d959ac60d47b46455a7ab0a38687c747c6d2d9e8c20ccf74dc6cdf145ec06805d4ac24a39aec2f5cd6e26e63e3d043a31c42411e4";

        vm.startPrank(admin);
        stakingContract.registerValidatorKeys(publicKeys, signatures);
        vm.stopPrank();
    }

    function testReinitialization() public {
        vm.expectRevert(abi.encodeWithSignature("AlreadyInitialized()"));
        stakingContract.initialize_1(admin, 0.1 ether, address(depositContract), withdrawalCredentials);
    }

    function testRegisterKeysUnauthorized() public {
        bytes[] memory publicKeys = new bytes[](1);
        publicKeys[
            0
        ] = hex"24a2e06ab1fab73c784748836c9e823f67de868a5d03442bab73d2d942a5692bcdca0c228facc1506894ee3233a6c4a3";

        bytes[] memory signatures = new bytes[](1);
        signatures[
            0
        ] = hex"e61d84053b75b684fa2bb180d28c7bf5258d96cf231686a36a61d58f37457064d405efd90db74b0c84b18fc48e57542726b1a73b631619717f9a7de162a33d1de7e96750cda2f632417f331ba5bb6441a3123151d82f4fd2793655af14904601";

        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        stakingContract.registerValidatorKeys(publicKeys, signatures);
    }

    function testRegisterKeys() public {
        bytes[] memory publicKeys = new bytes[](1);
        publicKeys[
            0
        ] = hex"24a2e06ab1fab73c784748836c9e823f67de868a5d03442bab73d2d942a5692bcdca0c228facc1506894ee3233a6c4a3";

        bytes[] memory signatures = new bytes[](1);
        signatures[
            0
        ] = hex"e61d84053b75b684fa2bb180d28c7bf5258d96cf231686a36a61d58f37457064d405efd90db74b0c84b18fc48e57542726b1a73b631619717f9a7de162a33d1de7e96750cda2f632417f331ba5bb6441a3123151d82f4fd2793655af14904601";

        assert(stakingContract.getKeyCount() == 10);
        vm.startPrank(admin);

        startMeasuringGas("registerValidatorKeys(bytes[],bytes[])");
        stakingContract.registerValidatorKeys(publicKeys, signatures);
        stopMeasuringGas();

        vm.stopPrank();
        assert(stakingContract.getKeyCount() == 11);
    }

    function testRegisterKeysInvalidPublicKey() public {
        bytes[] memory publicKeys = new bytes[](1);
        publicKeys[
            0
        ] = hex"24a2e06ab1fab73c784748836c9e823f67de868a5d03442bab73d2d942a5692bcdca0c228facc1506894ee3233a6c4";

        bytes[] memory signatures = new bytes[](1);
        signatures[
            0
        ] = hex"e61d84053b75b684fa2bb180d28c7bf5258d96cf231686a36a61d58f37457064d405efd90db74b0c84b18fc48e57542726b1a73b631619717f9a7de162a33d1de7e96750cda2f632417f331ba5bb6441a3123151d82f4fd2793655af14904601";

        assert(stakingContract.getKeyCount() == 10);
        vm.startPrank(admin);

        vm.expectRevert(abi.encodeWithSignature("InvalidArgument()"));
        stakingContract.registerValidatorKeys(publicKeys, signatures);
    }

    function testRegisterKeysInvalidSignature() public {
        bytes[] memory publicKeys = new bytes[](1);
        publicKeys[
            0
        ] = hex"24a2e06ab1fab73c784748836c9e823f67de868a5d03442bab73d2d942a5692bcdca0c228facc1506894ee3233a6c4a3";

        bytes[] memory signatures = new bytes[](1);
        signatures[
            0
        ] = hex"e61d84053b75b684fa2bb180d28c7bf5258d96cf231686a36a61d58f37457064d405efd90db74b0c84b18fc48e57542726b1a73b631619717f9a7de162a33d1de7e96750cda2f632417f331ba5bb6441a3123151d82f4fd2793655af149046";

        assert(stakingContract.getKeyCount() == 10);
        vm.startPrank(admin);

        vm.expectRevert(abi.encodeWithSignature("InvalidArgument()"));
        stakingContract.registerValidatorKeys(publicKeys, signatures);
    }

    function testRegisterKeysInvalidSignatureArrayLength() public {
        bytes[] memory publicKeys = new bytes[](1);
        publicKeys[
            0
        ] = hex"24a2e06ab1fab73c784748836c9e823f67de868a5d03442bab73d2d942a5692bcdca0c228facc1506894ee3233a6c4a3";

        bytes[] memory signatures = new bytes[](2);
        signatures[
            0
        ] = hex"e61d84053b75b684fa2bb180d28c7bf5258d96cf231686a36a61d58f37457064d405efd90db74b0c84b18fc48e57542726b1a73b631619717f9a7de162a33d1de7e96750cda2f632417f331ba5bb6441a3123151d82f4fd2793655af14904601";
        signatures[
            1
        ] = hex"2fc71d4bec4f87c108c09a98ac9bbb6203ed2208019d7a00128f494d47b4b6e77136decf1b804561bbc2e41339648ffe7304f48ed249edeca2c9238f5f5e7091be579cb62d6acb60e988749fc500196b461aa07f3fe0e2a2681f0dd4344c51ff";

        assert(stakingContract.getKeyCount() == 10);
        vm.startPrank(admin);

        vm.expectRevert(abi.encodeWithSignature("InvalidArgument()"));
        stakingContract.registerValidatorKeys(publicKeys, signatures);
    }

    function testRegisterKeysInvalidPublicKeyArrayLength() public {
        bytes[] memory publicKeys = new bytes[](2);
        publicKeys[
            0
        ] = hex"24a2e06ab1fab73c784748836c9e823f67de868a5d03442bab73d2d942a5692bcdca0c228facc1506894ee3233a6c4a3";
        publicKeys[
            1
        ] = hex"e0a8bf46aba4e979f97eb5534f0bae149f9d5f2b36c9bb7c2b5cb140799d6aebd57de9c9401a2fea4e90e139a9f05308";

        bytes[] memory signatures = new bytes[](1);
        signatures[
            0
        ] = hex"e61d84053b75b684fa2bb180d28c7bf5258d96cf231686a36a61d58f37457064d405efd90db74b0c84b18fc48e57542726b1a73b631619717f9a7de162a33d1de7e96750cda2f632417f331ba5bb6441a3123151d82f4fd2793655af14904601";

        assert(stakingContract.getKeyCount() == 10);
        vm.startPrank(admin);

        vm.expectRevert(abi.encodeWithSignature("InvalidArgument()"));
        stakingContract.registerValidatorKeys(publicKeys, signatures);
    }

    function testRegisterKeysEmptyArrays() public {
        bytes[] memory publicKeys = new bytes[](0);

        bytes[] memory signatures = new bytes[](0);

        assert(stakingContract.getKeyCount() == 10);
        vm.startPrank(admin);

        vm.expectRevert(abi.encodeWithSignature("InvalidArgument()"));
        stakingContract.registerValidatorKeys(publicKeys, signatures);
    }

    function testChangingFee() public {
        assertEq(stakingContract.getFee(), 0.1 ether);
        vm.startPrank(admin);
        startMeasuringGas("setFee");
        stakingContract.setFee(0.2 ether);
        stopMeasuringGas();
        vm.stopPrank();
        assertEq(stakingContract.getFee(), 0.2 ether);
    }

    function testChangingFeeUnauthorized() public {
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        stakingContract.setFee(0.2 ether);
    }

    function testDepositInvalidValueViaImplicitCall() public {
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        vm.expectRevert(abi.encodeWithSignature("InvalidValue()"));
        address(stakingContract).call{value: 32 ether}("");
        vm.stopPrank();
    }

    function testDepositOneValidatorViaImplicitCall() public {
        vm.deal(bob, 32 ether + 0.1 ether);
        vm.startPrank(bob);
        assert(stakingContract.getKeyCount() == 10);
        assert(stakingContract.getValidatorCount() == 0);
        assert(
            stakingContract.getWithdrawer(
                hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759"
            ) == address(0)
        );
        startMeasuringGas("receive() 1 validator");
        (bool ok, ) = address(stakingContract).call{value: 32 ether + 0.1 ether}("");
        stopMeasuringGas();
        assert(ok == true);
        assert(stakingContract.getKeyCount() == 10);
        assert(stakingContract.getValidatorCount() == 1);
        assert(
            stakingContract.getWithdrawer(
                hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759"
            ) == bob
        );
        vm.stopPrank();
    }

    function testDepositTenValidatorViaImplicitCall() public {
        vm.deal(bob, (32 ether + 0.1 ether) * 10);
        vm.startPrank(bob);

        assert(stakingContract.getKeyCount() == 10);
        assert(stakingContract.getValidatorCount() == 0);
        assert(
            stakingContract.getWithdrawer(
                hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"14451b3fb9288549aff6dea9843b43e0c47a3b856f307732175230e254c0004e48b02414987088ac7003e148930017b4"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"9a1a8d4600f33d463c4afc07bbfc82703c9fcf81a5891f90a71c86a02faff443c6c3b2592bd44d5d3d7a93cb4aaaa105"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"612496d61e68140a5418b468f872bf2f3e79f9cb0d9c3e889663fca02939b31e8ee3092203ee1417128e965c6406a07f"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"68abf2ebe2689cf6c853ef126ffa8574c2a7d913e28de9147fa6b96706ea5bf9eacd1aba06edeaee155009fb912c0007"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"0774cc64136fcffde12ed731260bc5529df64da298f493561198e9d6acf42cf21e853ae7b2df85f27d2183149969d623"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"b9237254c2cfe1d0082742eb042ac096d686dbe03c79ee31cbd03bb4682f8797043eed9f6e622814831ac5dfe1176552"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"fb7f9b6ff38a149ae1d8414097a32fd96da6453c52fda13e3402a09e2fa6886daa4300f09c73e4bc2901b99c44744c5c"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"fdca2994adc49ddccb195bda2510e50a4ae10de26cf96dee5e577689f51650a610a33da0a826ae47247d8d1189cb3386"
            ) == address(0)
        );

        startMeasuringGas("receive() 10 validators");
        (bool ok, ) = address(stakingContract).call{value: (32 ether + 0.1 ether) * 10}("");
        stopMeasuringGas();

        assert(ok == true);
        assert(stakingContract.getKeyCount() == 10);
        assert(stakingContract.getValidatorCount() == 10);
        assert(
            stakingContract.getWithdrawer(
                hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759"
            ) == bob
        );
        assert(
            stakingContract.getWithdrawer(
                hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060"
            ) == bob
        );
        assert(
            stakingContract.getWithdrawer(
                hex"14451b3fb9288549aff6dea9843b43e0c47a3b856f307732175230e254c0004e48b02414987088ac7003e148930017b4"
            ) == bob
        );
        assert(
            stakingContract.getWithdrawer(
                hex"9a1a8d4600f33d463c4afc07bbfc82703c9fcf81a5891f90a71c86a02faff443c6c3b2592bd44d5d3d7a93cb4aaaa105"
            ) == bob
        );
        assert(
            stakingContract.getWithdrawer(
                hex"612496d61e68140a5418b468f872bf2f3e79f9cb0d9c3e889663fca02939b31e8ee3092203ee1417128e965c6406a07f"
            ) == bob
        );
        assert(
            stakingContract.getWithdrawer(
                hex"68abf2ebe2689cf6c853ef126ffa8574c2a7d913e28de9147fa6b96706ea5bf9eacd1aba06edeaee155009fb912c0007"
            ) == bob
        );
        assert(
            stakingContract.getWithdrawer(
                hex"0774cc64136fcffde12ed731260bc5529df64da298f493561198e9d6acf42cf21e853ae7b2df85f27d2183149969d623"
            ) == bob
        );
        assert(
            stakingContract.getWithdrawer(
                hex"b9237254c2cfe1d0082742eb042ac096d686dbe03c79ee31cbd03bb4682f8797043eed9f6e622814831ac5dfe1176552"
            ) == bob
        );
        assert(
            stakingContract.getWithdrawer(
                hex"fb7f9b6ff38a149ae1d8414097a32fd96da6453c52fda13e3402a09e2fa6886daa4300f09c73e4bc2901b99c44744c5c"
            ) == bob
        );
        assert(
            stakingContract.getWithdrawer(
                hex"fdca2994adc49ddccb195bda2510e50a4ae10de26cf96dee5e577689f51650a610a33da0a826ae47247d8d1189cb3386"
            ) == bob
        );

        vm.stopPrank();
    }

    function testDepositElevenValidatorViaImplicitCall() public {
        vm.deal(bob, (32 ether + 0.1 ether) * 11);
        vm.startPrank(bob);
        assert(stakingContract.getKeyCount() == 10);
        assert(stakingContract.getValidatorCount() == 0);
        vm.expectRevert(abi.encodeWithSignature("NotEnoughKeys()"));
        address(stakingContract).call{value: (32 ether + 0.1 ether) * 11}("");
    }

    function testDepositFiveValidatorsTwiceViaImplicitCall() public {
        vm.deal(bob, (32 ether + 0.1 ether) * 10);
        vm.startPrank(bob);

        assert(stakingContract.getKeyCount() == 10);
        assert(stakingContract.getValidatorCount() == 0);
        assert(
            stakingContract.getWithdrawer(
                hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"14451b3fb9288549aff6dea9843b43e0c47a3b856f307732175230e254c0004e48b02414987088ac7003e148930017b4"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"9a1a8d4600f33d463c4afc07bbfc82703c9fcf81a5891f90a71c86a02faff443c6c3b2592bd44d5d3d7a93cb4aaaa105"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"612496d61e68140a5418b468f872bf2f3e79f9cb0d9c3e889663fca02939b31e8ee3092203ee1417128e965c6406a07f"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"68abf2ebe2689cf6c853ef126ffa8574c2a7d913e28de9147fa6b96706ea5bf9eacd1aba06edeaee155009fb912c0007"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"0774cc64136fcffde12ed731260bc5529df64da298f493561198e9d6acf42cf21e853ae7b2df85f27d2183149969d623"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"b9237254c2cfe1d0082742eb042ac096d686dbe03c79ee31cbd03bb4682f8797043eed9f6e622814831ac5dfe1176552"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"fb7f9b6ff38a149ae1d8414097a32fd96da6453c52fda13e3402a09e2fa6886daa4300f09c73e4bc2901b99c44744c5c"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"fdca2994adc49ddccb195bda2510e50a4ae10de26cf96dee5e577689f51650a610a33da0a826ae47247d8d1189cb3386"
            ) == address(0)
        );

        startMeasuringGas("receive() 5 validators");
        (bool ok, ) = address(stakingContract).call{value: (32 ether + 0.1 ether) * 5}("");
        stopMeasuringGas();

        assert(ok == true);
        assert(stakingContract.getKeyCount() == 10);
        assert(stakingContract.getValidatorCount() == 5);
        assert(
            stakingContract.getWithdrawer(
                hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759"
            ) == bob
        );
        assert(
            stakingContract.getWithdrawer(
                hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060"
            ) == bob
        );
        assert(
            stakingContract.getWithdrawer(
                hex"14451b3fb9288549aff6dea9843b43e0c47a3b856f307732175230e254c0004e48b02414987088ac7003e148930017b4"
            ) == bob
        );
        assert(
            stakingContract.getWithdrawer(
                hex"9a1a8d4600f33d463c4afc07bbfc82703c9fcf81a5891f90a71c86a02faff443c6c3b2592bd44d5d3d7a93cb4aaaa105"
            ) == bob
        );
        assert(
            stakingContract.getWithdrawer(
                hex"612496d61e68140a5418b468f872bf2f3e79f9cb0d9c3e889663fca02939b31e8ee3092203ee1417128e965c6406a07f"
            ) == bob
        );
        assert(
            stakingContract.getWithdrawer(
                hex"68abf2ebe2689cf6c853ef126ffa8574c2a7d913e28de9147fa6b96706ea5bf9eacd1aba06edeaee155009fb912c0007"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"0774cc64136fcffde12ed731260bc5529df64da298f493561198e9d6acf42cf21e853ae7b2df85f27d2183149969d623"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"b9237254c2cfe1d0082742eb042ac096d686dbe03c79ee31cbd03bb4682f8797043eed9f6e622814831ac5dfe1176552"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"fb7f9b6ff38a149ae1d8414097a32fd96da6453c52fda13e3402a09e2fa6886daa4300f09c73e4bc2901b99c44744c5c"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"fdca2994adc49ddccb195bda2510e50a4ae10de26cf96dee5e577689f51650a610a33da0a826ae47247d8d1189cb3386"
            ) == address(0)
        );

        startMeasuringGas("receive() 5 validators");
        (ok, ) = address(stakingContract).call{value: (32 ether + 0.1 ether) * 5}("");
        stopMeasuringGas();

        assert(ok == true);
        assert(stakingContract.getKeyCount() == 10);
        assert(stakingContract.getValidatorCount() == 10);
        assert(
            stakingContract.getWithdrawer(
                hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759"
            ) == bob
        );
        assert(
            stakingContract.getWithdrawer(
                hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060"
            ) == bob
        );
        assert(
            stakingContract.getWithdrawer(
                hex"14451b3fb9288549aff6dea9843b43e0c47a3b856f307732175230e254c0004e48b02414987088ac7003e148930017b4"
            ) == bob
        );
        assert(
            stakingContract.getWithdrawer(
                hex"9a1a8d4600f33d463c4afc07bbfc82703c9fcf81a5891f90a71c86a02faff443c6c3b2592bd44d5d3d7a93cb4aaaa105"
            ) == bob
        );
        assert(
            stakingContract.getWithdrawer(
                hex"612496d61e68140a5418b468f872bf2f3e79f9cb0d9c3e889663fca02939b31e8ee3092203ee1417128e965c6406a07f"
            ) == bob
        );
        assert(
            stakingContract.getWithdrawer(
                hex"68abf2ebe2689cf6c853ef126ffa8574c2a7d913e28de9147fa6b96706ea5bf9eacd1aba06edeaee155009fb912c0007"
            ) == bob
        );
        assert(
            stakingContract.getWithdrawer(
                hex"0774cc64136fcffde12ed731260bc5529df64da298f493561198e9d6acf42cf21e853ae7b2df85f27d2183149969d623"
            ) == bob
        );
        assert(
            stakingContract.getWithdrawer(
                hex"b9237254c2cfe1d0082742eb042ac096d686dbe03c79ee31cbd03bb4682f8797043eed9f6e622814831ac5dfe1176552"
            ) == bob
        );
        assert(
            stakingContract.getWithdrawer(
                hex"fb7f9b6ff38a149ae1d8414097a32fd96da6453c52fda13e3402a09e2fa6886daa4300f09c73e4bc2901b99c44744c5c"
            ) == bob
        );
        assert(
            stakingContract.getWithdrawer(
                hex"fdca2994adc49ddccb195bda2510e50a4ae10de26cf96dee5e577689f51650a610a33da0a826ae47247d8d1189cb3386"
            ) == bob
        );

        vm.stopPrank();
    }

    function testDepositInvalidValueViaExplicitCall() public {
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        vm.expectRevert(abi.encodeWithSignature("InvalidValue()"));
        stakingContract.deposit{value: 32 ether}(bob);
        vm.stopPrank();
    }

    function testDepositOneValidatorViaExplicitCall() public {
        vm.deal(bob, 32 ether + 0.1 ether);
        vm.startPrank(bob);
        assert(stakingContract.getKeyCount() == 10);
        assert(stakingContract.getValidatorCount() == 0);
        assert(
            stakingContract.getWithdrawer(
                hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759"
            ) == address(0)
        );
        startMeasuringGas("deposit(address) 1 validator");
        stakingContract.deposit{value: 32 ether + 0.1 ether}(alice);
        stopMeasuringGas();
        assert(stakingContract.getKeyCount() == 10);
        assert(stakingContract.getValidatorCount() == 1);
        assert(
            stakingContract.getWithdrawer(
                hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759"
            ) == alice
        );
        vm.stopPrank();
    }

    function testDepositTenValidatorViaExplicitCall() public {
        vm.deal(bob, (32 ether + 0.1 ether) * 10);
        vm.startPrank(bob);

        assert(stakingContract.getKeyCount() == 10);
        assert(stakingContract.getValidatorCount() == 0);
        assert(
            stakingContract.getWithdrawer(
                hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"14451b3fb9288549aff6dea9843b43e0c47a3b856f307732175230e254c0004e48b02414987088ac7003e148930017b4"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"9a1a8d4600f33d463c4afc07bbfc82703c9fcf81a5891f90a71c86a02faff443c6c3b2592bd44d5d3d7a93cb4aaaa105"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"612496d61e68140a5418b468f872bf2f3e79f9cb0d9c3e889663fca02939b31e8ee3092203ee1417128e965c6406a07f"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"68abf2ebe2689cf6c853ef126ffa8574c2a7d913e28de9147fa6b96706ea5bf9eacd1aba06edeaee155009fb912c0007"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"0774cc64136fcffde12ed731260bc5529df64da298f493561198e9d6acf42cf21e853ae7b2df85f27d2183149969d623"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"b9237254c2cfe1d0082742eb042ac096d686dbe03c79ee31cbd03bb4682f8797043eed9f6e622814831ac5dfe1176552"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"fb7f9b6ff38a149ae1d8414097a32fd96da6453c52fda13e3402a09e2fa6886daa4300f09c73e4bc2901b99c44744c5c"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"fdca2994adc49ddccb195bda2510e50a4ae10de26cf96dee5e577689f51650a610a33da0a826ae47247d8d1189cb3386"
            ) == address(0)
        );

        startMeasuringGas("deposit(address) 10 validators");
        stakingContract.deposit{value: (32 ether + 0.1 ether) * 10}(alice);
        stopMeasuringGas();

        assert(stakingContract.getKeyCount() == 10);
        assert(stakingContract.getValidatorCount() == 10);
        assert(
            stakingContract.getWithdrawer(
                hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759"
            ) == alice
        );
        assert(
            stakingContract.getWithdrawer(
                hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060"
            ) == alice
        );
        assert(
            stakingContract.getWithdrawer(
                hex"14451b3fb9288549aff6dea9843b43e0c47a3b856f307732175230e254c0004e48b02414987088ac7003e148930017b4"
            ) == alice
        );
        assert(
            stakingContract.getWithdrawer(
                hex"9a1a8d4600f33d463c4afc07bbfc82703c9fcf81a5891f90a71c86a02faff443c6c3b2592bd44d5d3d7a93cb4aaaa105"
            ) == alice
        );
        assert(
            stakingContract.getWithdrawer(
                hex"612496d61e68140a5418b468f872bf2f3e79f9cb0d9c3e889663fca02939b31e8ee3092203ee1417128e965c6406a07f"
            ) == alice
        );
        assert(
            stakingContract.getWithdrawer(
                hex"68abf2ebe2689cf6c853ef126ffa8574c2a7d913e28de9147fa6b96706ea5bf9eacd1aba06edeaee155009fb912c0007"
            ) == alice
        );
        assert(
            stakingContract.getWithdrawer(
                hex"0774cc64136fcffde12ed731260bc5529df64da298f493561198e9d6acf42cf21e853ae7b2df85f27d2183149969d623"
            ) == alice
        );
        assert(
            stakingContract.getWithdrawer(
                hex"b9237254c2cfe1d0082742eb042ac096d686dbe03c79ee31cbd03bb4682f8797043eed9f6e622814831ac5dfe1176552"
            ) == alice
        );
        assert(
            stakingContract.getWithdrawer(
                hex"fb7f9b6ff38a149ae1d8414097a32fd96da6453c52fda13e3402a09e2fa6886daa4300f09c73e4bc2901b99c44744c5c"
            ) == alice
        );
        assert(
            stakingContract.getWithdrawer(
                hex"fdca2994adc49ddccb195bda2510e50a4ae10de26cf96dee5e577689f51650a610a33da0a826ae47247d8d1189cb3386"
            ) == alice
        );

        vm.stopPrank();
    }

    function testDepositElevenValidatorViaExplicitCall() public {
        vm.deal(bob, (32 ether + 0.1 ether) * 11);
        vm.startPrank(bob);
        assert(stakingContract.getKeyCount() == 10);
        assert(stakingContract.getValidatorCount() == 0);
        vm.expectRevert(abi.encodeWithSignature("NotEnoughKeys()"));
        stakingContract.deposit{value: (32 ether + 0.1 ether) * 11}(alice);
    }

    function testDepositFiveValidatorsTwiceViaExplicitCall() public {
        vm.deal(bob, (32 ether + 0.1 ether) * 10);
        vm.startPrank(bob);

        assert(stakingContract.getKeyCount() == 10);
        assert(stakingContract.getValidatorCount() == 0);
        assert(
            stakingContract.getWithdrawer(
                hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"14451b3fb9288549aff6dea9843b43e0c47a3b856f307732175230e254c0004e48b02414987088ac7003e148930017b4"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"9a1a8d4600f33d463c4afc07bbfc82703c9fcf81a5891f90a71c86a02faff443c6c3b2592bd44d5d3d7a93cb4aaaa105"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"612496d61e68140a5418b468f872bf2f3e79f9cb0d9c3e889663fca02939b31e8ee3092203ee1417128e965c6406a07f"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"68abf2ebe2689cf6c853ef126ffa8574c2a7d913e28de9147fa6b96706ea5bf9eacd1aba06edeaee155009fb912c0007"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"0774cc64136fcffde12ed731260bc5529df64da298f493561198e9d6acf42cf21e853ae7b2df85f27d2183149969d623"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"b9237254c2cfe1d0082742eb042ac096d686dbe03c79ee31cbd03bb4682f8797043eed9f6e622814831ac5dfe1176552"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"fb7f9b6ff38a149ae1d8414097a32fd96da6453c52fda13e3402a09e2fa6886daa4300f09c73e4bc2901b99c44744c5c"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"fdca2994adc49ddccb195bda2510e50a4ae10de26cf96dee5e577689f51650a610a33da0a826ae47247d8d1189cb3386"
            ) == address(0)
        );

        startMeasuringGas("deposit(address) 5 validators");
        stakingContract.deposit{value: (32 ether + 0.1 ether) * 5}(alice);
        stopMeasuringGas();

        assert(stakingContract.getKeyCount() == 10);
        assert(stakingContract.getValidatorCount() == 5);
        assert(
            stakingContract.getWithdrawer(
                hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759"
            ) == alice
        );
        assert(
            stakingContract.getWithdrawer(
                hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060"
            ) == alice
        );
        assert(
            stakingContract.getWithdrawer(
                hex"14451b3fb9288549aff6dea9843b43e0c47a3b856f307732175230e254c0004e48b02414987088ac7003e148930017b4"
            ) == alice
        );
        assert(
            stakingContract.getWithdrawer(
                hex"9a1a8d4600f33d463c4afc07bbfc82703c9fcf81a5891f90a71c86a02faff443c6c3b2592bd44d5d3d7a93cb4aaaa105"
            ) == alice
        );
        assert(
            stakingContract.getWithdrawer(
                hex"612496d61e68140a5418b468f872bf2f3e79f9cb0d9c3e889663fca02939b31e8ee3092203ee1417128e965c6406a07f"
            ) == alice
        );
        assert(
            stakingContract.getWithdrawer(
                hex"68abf2ebe2689cf6c853ef126ffa8574c2a7d913e28de9147fa6b96706ea5bf9eacd1aba06edeaee155009fb912c0007"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"0774cc64136fcffde12ed731260bc5529df64da298f493561198e9d6acf42cf21e853ae7b2df85f27d2183149969d623"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"b9237254c2cfe1d0082742eb042ac096d686dbe03c79ee31cbd03bb4682f8797043eed9f6e622814831ac5dfe1176552"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"fb7f9b6ff38a149ae1d8414097a32fd96da6453c52fda13e3402a09e2fa6886daa4300f09c73e4bc2901b99c44744c5c"
            ) == address(0)
        );
        assert(
            stakingContract.getWithdrawer(
                hex"fdca2994adc49ddccb195bda2510e50a4ae10de26cf96dee5e577689f51650a610a33da0a826ae47247d8d1189cb3386"
            ) == address(0)
        );

        startMeasuringGas("deposit(address) 5 validators");
        stakingContract.deposit{value: (32 ether + 0.1 ether) * 5}(bob);
        stopMeasuringGas();

        assert(stakingContract.getKeyCount() == 10);
        assert(stakingContract.getValidatorCount() == 10);
        assert(
            stakingContract.getWithdrawer(
                hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759"
            ) == alice
        );
        assert(
            stakingContract.getWithdrawer(
                hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060"
            ) == alice
        );
        assert(
            stakingContract.getWithdrawer(
                hex"14451b3fb9288549aff6dea9843b43e0c47a3b856f307732175230e254c0004e48b02414987088ac7003e148930017b4"
            ) == alice
        );
        assert(
            stakingContract.getWithdrawer(
                hex"9a1a8d4600f33d463c4afc07bbfc82703c9fcf81a5891f90a71c86a02faff443c6c3b2592bd44d5d3d7a93cb4aaaa105"
            ) == alice
        );
        assert(
            stakingContract.getWithdrawer(
                hex"612496d61e68140a5418b468f872bf2f3e79f9cb0d9c3e889663fca02939b31e8ee3092203ee1417128e965c6406a07f"
            ) == alice
        );
        assert(
            stakingContract.getWithdrawer(
                hex"68abf2ebe2689cf6c853ef126ffa8574c2a7d913e28de9147fa6b96706ea5bf9eacd1aba06edeaee155009fb912c0007"
            ) == bob
        );
        assert(
            stakingContract.getWithdrawer(
                hex"0774cc64136fcffde12ed731260bc5529df64da298f493561198e9d6acf42cf21e853ae7b2df85f27d2183149969d623"
            ) == bob
        );
        assert(
            stakingContract.getWithdrawer(
                hex"b9237254c2cfe1d0082742eb042ac096d686dbe03c79ee31cbd03bb4682f8797043eed9f6e622814831ac5dfe1176552"
            ) == bob
        );
        assert(
            stakingContract.getWithdrawer(
                hex"fb7f9b6ff38a149ae1d8414097a32fd96da6453c52fda13e3402a09e2fa6886daa4300f09c73e4bc2901b99c44744c5c"
            ) == bob
        );
        assert(
            stakingContract.getWithdrawer(
                hex"fdca2994adc49ddccb195bda2510e50a4ae10de26cf96dee5e577689f51650a610a33da0a826ae47247d8d1189cb3386"
            ) == bob
        );

        vm.stopPrank();
    }

    function testChangeWithdrawer() public {
        vm.deal(bob, 32 ether + 0.1 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether + 0.1 ether}(bob);
        assert(
            stakingContract.getWithdrawer(
                hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759"
            ) == bob
        );
        startMeasuringGas("setWithdrawer(bytes,address)");
        stakingContract.setWithdrawer(
            hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759",
            alice
        );
        stopMeasuringGas();
        assert(
            stakingContract.getWithdrawer(
                hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759"
            ) == alice
        );
        vm.stopPrank();
    }

    function testChangeWithdrawerUnauthorized() public {
        vm.deal(bob, 32 ether + 0.1 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether + 0.1 ether}(alice);
        assert(
            stakingContract.getWithdrawer(
                hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759"
            ) == alice
        );
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        stakingContract.setWithdrawer(
            hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759",
            alice
        );
        vm.stopPrank();
    }
}
