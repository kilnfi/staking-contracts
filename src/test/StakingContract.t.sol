//SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.10;

import "forge-std/Test.sol";
import "../contracts/StakingContract.sol";
import "../contracts/interfaces/IDepositContract.sol";
import "../contracts/libs/BytesLib.sol";
import "../contracts/ConsensusLayerFeeDispatcher.sol";
import "../contracts/ExecutionLayerFeeDispatcher.sol";
import "../contracts/FeeRecipient.sol";
import "../contracts/TUPProxy.sol";

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

// 10 PUBLIC KEYS
bytes constant PUBLIC_KEYS = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e06014451b3fb9288549aff6dea9843b43e0c47a3b856f307732175230e254c0004e48b02414987088ac7003e148930017b49a1a8d4600f33d463c4afc07bbfc82703c9fcf81a5891f90a71c86a02faff443c6c3b2592bd44d5d3d7a93cb4aaaa105612496d61e68140a5418b468f872bf2f3e79f9cb0d9c3e889663fca02939b31e8ee3092203ee1417128e965c6406a07f68abf2ebe2689cf6c853ef126ffa8574c2a7d913e28de9147fa6b96706ea5bf9eacd1aba06edeaee155009fb912c00070774cc64136fcffde12ed731260bc5529df64da298f493561198e9d6acf42cf21e853ae7b2df85f27d2183149969d623b9237254c2cfe1d0082742eb042ac096d686dbe03c79ee31cbd03bb4682f8797043eed9f6e622814831ac5dfe1176552fb7f9b6ff38a149ae1d8414097a32fd96da6453c52fda13e3402a09e2fa6886daa4300f09c73e4bc2901b99c44744c5cfdca2994adc49ddccb195bda2510e50a4ae10de26cf96dee5e577689f51650a610a33da0a826ae47247d8d1189cb3386";
bytes constant PUBLIC_KEYS_2 = hex"0c74b6d3d877bbb2083f1bcc83b302f3ed533eaf3cd39cff97daf2c7b9b776168481aa7b51778df673a37049886f25b07f03dbc79d85fa9d41f9eefa8e598353b652aadf497673744527c73127f872b91cf31ec8041dae1b3a4238683cf442ea23a95fe68b400ab42b14e8c99280a057d1d840e80723c3622b38e6acd1f471bf247cf62312c9b863a75ac0d270cefa4f84fd8586dbda15c67c1a46e85cf56c60550f54cb082770baf3d2bbf4c33f5254bd0b93e017f3ed036b13baec41bb69085f9eff48651be38c8f9e1f67b643f84ec356864aaa057f0042b121b9d040ed9be3f5cc9cc659d8f8fc02575ed3c25708adac2c8d0c50ab7e4599ce9edf300d98e1cfcfc8e0022a24c712f0769de99a3389bac1cdca92ae20fba323142fe2e8d09ef2cb59c3f822779b3fe6410cddce7255d35db01093cc435c0a35bbb4cd8d4eb3bd2cc597c49a7a909c16f67fe8b6702d5d0c22ad189b1c45325190015b0017606f768c7aa2006cc19dfeb5f367eae9dd17a5c307705db1f5cec552fc038e5fa3a76352d9621a4d74b1fd7e1707c7bfb5e912e2b5a33a2f34a419055d0c4065aa787f743aff953d73441e96ffc9b0f5a3248c23398518a758aec8451b626bff7eed063a3b11bf661d10ad6dac5ee62f47be125e3c668e14b3c704d736b4fbff";

bytes constant PUBKEY_1 = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
bytes constant PUBKEY_2 = hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060";
bytes constant PUBKEY_10 = hex"fdca2994adc49ddccb195bda2510e50a4ae10de26cf96dee5e577689f51650a610a33da0a826ae47247d8d1189cb3386";

bytes constant PUBKEY_2_1 = hex"0c74b6d3d877bbb2083f1bcc83b302f3ed533eaf3cd39cff97daf2c7b9b776168481aa7b51778df673a37049886f25b0";

// 10 SIGNATURES
bytes constant SIGNATURES = hex"ccb81f4485957f440bc17dbe760f374cbb112c6f12fa10e8709fac4522b30440d918c7bb867fa04f6b3cfbd977455f8f2fde586fdf3d7baa429e98e497ff871f3b8db1528b2b964fa24d26e377c74746496cc719c50dbf391fb3f74f5ca4b93a02a9f0007cd7b7d2af2d1b07c8600ab86a5d27dc51a29c2e3007c7a69cb73bcaecc764641e02370955dba100428d259d6475ee3566872bd43b0e73e55b9669e50f2b1666e57b326a5dfad655c7921e0dfb421b1ec59c8fdb48eb77421fd06966f393d619cbf13ff427df11dcb17026df25f35268de5b168e359c16f2a3d5fbc6376db44638d773c851c875f21222448433d285920e8bdc4f5cbff130d7387c0a9589324286aea398e5aacad3bbfe3992dfce62571f0e282ed9c29e3fa5b07aa5c81749589b1170d3b85a84331e2f6b8e26eadebfd569b225759f40bbd12d6c3d253ed3f379b014b2ea44cce54d362072e2d020ff139a903b7d87fc3fddc2e6657c83e0b79851c22c6e0e477463463c97d6cc0e2e2de5e35b227bddb285521be3766358abaf3159d89f68c9770e28278f177088cfc4089b817effaaecabdffa4e66427868b105cb9348ea2d84eeea059a5d1ff3277d6f9cf656fc973d07cabed70fb8f8eb2798a65d207a8e1f8a26910949db9fa62d62bc15ecc097a93a27a1873405b8589a4ddf0ecf0303c6031484562b32eb7881975026524d6d4a9de6cd73fe2c324501586b9b6fa6bce950bbd21472278302f83dbfd6be036f2fc36d299d66578e844be3d6aa8314fab468f038fd6e130ada0a886fccfb2fd843f7dd07e8968401bbe2af7345fce52ba4b310b30af2d54b15669d06c206682c1730ab6b17787e361f04401f78dc5cbd5fac955df4e83c24cdabfabdb3f4ea40961d04a5ca166c17694fca144025b47131a68ddb230d36fe6e831e82624c9a925d706bff86982852b26ebf019a3f6ee36aedbbc6bec2d50531a233e09225493d3c5fd48379aec373baf622fb9feed6261e5296e5ae6601e7523c7f386801ed63a344b07106a0d03e5848209db5e114c0e67884916a43a1bfb77d9b8ea113c3ba8cad4b006aafeadcc31e70e85c5efecaf807154d011c1413340d4b592d2f270fb48b2050e08493c1427ddfac8dcc27fe434d32a35dcbddbcb1c4e22ead6734a4ac910f6768bc9ff6b355c1151695e41121cdcc9d9d3b18cf4d66ca3c1db0527c471a0dcf256590602a7269dcb26175e7eb370bd9794ac8ab558bea69e6a92d8e818b675a80e2df0516b8307291d93cb85d959ac60d47b46455a7ab0a38687c747c6d2d9e8c20ccf74dc6cdf145ec06805d4ac24a39aec2f5cd6e26e63e3d043a31c42411e4";
bytes constant SIGNATURES_2 = hex"fe41ffbe702fb08d01063c9cd99fac11a16e921c784e681e365db00c4bd6760df67cfc0d0555a8ee8bf534a2c0987b7949b18dba726ced579240fa063274bc7ab25e44b758c452c433debfebbc075cbe105f07502402a9591dc891640a9f2b34fe0863bf987ff4b5a601b0ffcecc185f04847e0b97d3fb9457c32efb9c3ce35520308cfcc8ca78d5d4da164f6d1575d32fe466b8076bc4056ad97fa3e3607a60e5e420bdec413e5ffcc3119b1b89a957b14a437e009a858c4c40c0f1fc7f3d1ad83bc96ada6c2c772260637774e5fbdc60791db6de3a31e136c28106b35c21932a8ed610306f0723675730e31d3deceff4f912e6070c9efcd6e3f0c9ad4a0e203f437f21679b87d46351714b5a1b6226f8ffadd19e18f85c918461ab67291e1c8cdfdc05280adf2b923f1269cf7de8bd351a7ede13524e836cbfc7ba22db91aaa5c9a0729a469985f5bd844347ba9a9b4019f4ad42c2025457cf48557494ac3ce6e311a1ded3e903cd3009d18133015d445d02a3ce3858781b582d28701a311ddb271f8a0c91c65b32cc13c512c35e5be9bb9dc556dfd3249a3733f58426718974820f17b3242a089e29b129fcea37c8b84996e2c725b59efccee24068625584e583700346f823ce92e11ac9db5964ca6300905c5e9f294330037ec1cb7d9b8fc28829b98fcc0fc405afcd54f43cb4a14e8cab3f5aa979fe2c3492fe295e1a50170e8857bd94e5b009bcec9626e6eb137b272882037202da7329dadcb5b99bbd7835b8875d696dab41774dcb559bfb4c79a5337efc5f1606bc7c2752389a49b6a578f0c7c58e2bf9efc55eef19beaf3de94da90c712ca3891ac71a6ff6d778a1c0c31f77fdde2c4b7f29adf8ccf000050e9e4829d2de36fda8d6b26020e6f0ece339e9ad96c01b166301238e1aaa30ddfb978968361a5f9d3fcaa381973c967c0dd88c6d54d00fa375ab4df3be57c4360b69d7634e95e4d4201da8f2348d0ce53be690146f0049d5d173a635d21406b10ed23ec9996bd0a43b812df363986fb8dedf5be1cdb3f85a5090460511af617507d24657e3733310b42e1406070a0316620037da35c5227bb85d3aacf3aebf750265838994e03a8770cdc1c31723ca1037232c32d21f31eee561575b18b1b4c0f027f270898aed60ab4bfe41160cd989cd5bdfeb795097ff01cd0ff41fea96311e92798c0a619aa957772cfd408747fc30dcb39210839a4c70b87d3ad881207fa5eee926bc2c6936ce10b382c7a37606d40bb1cf2637768255aae4a4cd18ed7004e3046520bea92c66a7074e4b46d3d566703e44d0c3f9ef49a2ff30632fe3f6a409178db66423809514cd7473f83d21";

bytes constant SIGNATURE_1 = hex"ccb81f4485957f440bc17dbe760f374cbb112c6f12fa10e8709fac4522b30440d918c7bb867fa04f6b3cfbd977455f8f2fde586fdf3d7baa429e98e497ff871f3b8db1528b2b964fa24d26e377c74746496cc719c50dbf391fb3f74f5ca4b93a";
bytes constant SIGNATURE_2 = hex"02a9f0007cd7b7d2af2d1b07c8600ab86a5d27dc51a29c2e3007c7a69cb73bcaecc764641e02370955dba100428d259d6475ee3566872bd43b0e73e55b9669e50f2b1666e57b326a5dfad655c7921e0dfb421b1ec59c8fdb48eb77421fd06966";

uint256 constant OPERATOR_INDEX = 0;

contract StakingContractTest is Test {
    address internal treasury;
    StakingContract internal stakingContract;
    DepositContractMock internal depositContract;

    address internal admin;
    address internal bob;
    address internal alice;
    address internal operator;
    address internal feeRecipient;
    address internal elDispatcher;
    address internal clDispatcher;
    address internal feeRecipientImpl;

    bytes32 salt = bytes32(0);

    event Deposit(address indexed caller, address indexed withdrawer, bytes publicKey, bytes signature);
    event ValidatorKeysAdded(uint256 indexed operatorIndex, bytes publicKey, bytes signatures);
    event ValidatorKeyRemoved(uint256 indexed operatorIndex, bytes publicKey);

    string internal checkpointLabel;
    uint256 internal checkpointGasLeft = 1; // Start the slot warm.
    uint256 internal lastMeasure;

    function startMeasure(string memory label) internal virtual {
        checkpointLabel = label;

        checkpointGasLeft = gasleft();
    }

    function stopMeasure() internal virtual {
        uint256 checkpointGasLeft2 = gasleft();

        // Subtract 100 to account for the warm SLOAD in startMeasuringGas.
        uint256 gasDelta = checkpointGasLeft - checkpointGasLeft2 - 100;

        lastMeasure = gasDelta;
    }

    function testLoopedDeposit() external {
        for (uint256 idx = 0; idx < 250; ++idx) {
            vm.startPrank(operator);
            bytes memory pubkey = genBytes(25 * 48);
            bytes memory sigs = genBytes(25 * 96);
            startMeasure("");
            stakingContract.addValidators(OPERATOR_INDEX, 25, pubkey, sigs);
            stopMeasure();
            uint256 gasCost = lastMeasure;
            if (gasCost > 6000000) {
                revert("GAS INCREASING");
            }
            vm.stopPrank();
        }
    }

    function genBytes(uint256 len) internal returns (bytes memory) {
        bytes memory res = "";
        while (res.length < len) {
            salt = keccak256(abi.encodePacked(salt));
            if (len - res.length >= 32) {
                res = BytesLib.concat(res, abi.encode(salt));
            } else {
                res = BytesLib.concat(res, BytesLib.slice(abi.encode(salt), 0, len - res.length));
            }
        }
        return res;
    }

    function setUp() public {
        admin = makeAddr("admin");
        bob = makeAddr("bob");
        alice = makeAddr("alice");
        operator = makeAddr("operator");
        feeRecipient = makeAddr("feeRecipient");
        clDispatcher = makeAddr("clDispatcher");
        elDispatcher = makeAddr("elDispatcher");
        feeRecipientImpl = makeAddr("feeRecipientImpl");
        treasury = makeAddr("treasury");

        stakingContract = new StakingContract();
        depositContract = new DepositContractMock();
        stakingContract.initialize_1(
            admin,
            treasury,
            address(depositContract),
            clDispatcher,
            elDispatcher,
            feeRecipientImpl,
            1000,
            2000,
            2000,
            5000
        );

        vm.startPrank(admin);
        stakingContract.addOperator(operator, feeRecipient);
        vm.stopPrank();

        {
            vm.startPrank(operator);
            stakingContract.addValidators(OPERATOR_INDEX, 10, PUBLIC_KEYS, SIGNATURES);
            vm.stopPrank();
        }

        {
            vm.startPrank(admin);
            stakingContract.setOperatorLimit(OPERATOR_INDEX, 10, block.number);
            vm.stopPrank();
        }
    }

    function testGetAdmin() public view {
        assertEq(stakingContract.getAdmin(), admin);
    }

    event BeginOwnershipTransfer(address indexed previousAdmin, address indexed newAdmin);
    event ChangedAdmin(address newAdmin);

    function testSetAdmin(address newAdmin) public {
        assertEq(stakingContract.getAdmin(), admin);

        // Start ownership transfer process.
        vm.startPrank(admin);
        vm.expectEmit(true, true, true, true);
        emit BeginOwnershipTransfer(admin, newAdmin);
        stakingContract.transferOwnership(newAdmin);
        vm.stopPrank();
        // At this point, the old admin is still in charge.
        assertEq(stakingContract.getAdmin(), admin);
        assertEq(stakingContract.getPendingAdmin(), newAdmin);

        // New admin accepts transfer.
        vm.startPrank(newAdmin);
        vm.expectEmit(true, true, true, true);
        emit ChangedAdmin(newAdmin);
        stakingContract.acceptOwnership();
        vm.stopPrank();

        assertEq(stakingContract.getAdmin(), newAdmin);
    }

    function testReinitialization() public {
        vm.expectRevert(abi.encodeWithSignature("AlreadyInitialized()"));
        stakingContract.initialize_1(
            admin,
            address(treasury),
            address(depositContract),
            address(0),
            address(0),
            address(0),
            1000,
            2000,
            2000,
            5000
        );
    }

    function testTransferOwnershipUnauthorized(address newAdmin) public {
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        stakingContract.transferOwnership(newAdmin);
    }

    function testAcceptOwnershipUnauthorized(address newAdmin, address randomUser) public {
        vm.assume(randomUser != newAdmin);
        vm.startPrank(admin);
        stakingContract.transferOwnership(newAdmin);
        vm.stopPrank();

        // A random user tries to accept new admin's role.
        vm.startPrank(randomUser);
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        stakingContract.acceptOwnership();
        vm.stopPrank();
    }

    function testGetOperator() public view {
        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        ) = stakingContract.getOperator(OPERATOR_INDEX);
        assertEq(operatorAddress, operator);
        assertEq(feeRecipientAddress, feeRecipient);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 0);
        assertEq(available, 10);
        assert(deactivated == false);
    }

    function testAddOperatorUnauthorized(address newOperator, address newOperatorFeeRecipient) public {
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        stakingContract.addOperator(newOperator, newOperatorFeeRecipient);
    }

    function testSetOperatorAddresses(address newOperatorFeeRecipient, address updatedOperator) public {
        vm.assume(newOperatorFeeRecipient != address(0));
        vm.assume(updatedOperator != address(0));

        // Try to update the operator address
        vm.startPrank(feeRecipient);
        stakingContract.setOperatorAddresses(OPERATOR_INDEX, updatedOperator, newOperatorFeeRecipient);
        vm.stopPrank();

        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        ) = stakingContract.getOperator(OPERATOR_INDEX);
        assertEq(operatorAddress, updatedOperator);
        assertEq(feeRecipientAddress, newOperatorFeeRecipient);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 0);
        assertEq(available, 10);
        assert(deactivated == false);
    }

    function testSetOperatorAddressesUnauthorized(address newOperator, address wrongOperatorFeeRecipient) public {
        // Try to update the operator addresses
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        stakingContract.setOperatorAddresses(OPERATOR_INDEX, newOperator, wrongOperatorFeeRecipient);
    }

    event ChangedOperatorLimit(uint256 operatorIndex, uint256 limit);

    function testSetOperatorLimit(uint8 _limit) public {
        (, , uint256 limit, , , , ) = stakingContract.getOperator(OPERATOR_INDEX);
        assertEq(limit, 10);

        if (_limit > 0) {
            vm.startPrank(operator);
            stakingContract.addValidators(
                OPERATOR_INDEX,
                _limit,
                genBytes(48 * uint256(_limit)),
                genBytes(96 * uint256(_limit))
            );
            vm.stopPrank();
        }

        vm.startPrank(admin);
        vm.expectEmit(true, true, true, true);
        emit ChangedOperatorLimit(OPERATOR_INDEX, _limit);
        stakingContract.setOperatorLimit(OPERATOR_INDEX, _limit, block.number);
        vm.stopPrank();

        (, , limit, , , , ) = stakingContract.getOperator(OPERATOR_INDEX);
        assertEq(limit, _limit);
    }

    function testSetOperatorLimit_snapshotRevert(uint8 _limit) public {
        vm.assume(_limit > 10); // Ensuring we raise the existing limit

        (, , uint256 limit, , , , ) = stakingContract.getOperator(OPERATOR_INDEX);
        assertEq(limit, 10);

        vm.roll(1000);
        if (_limit > 0) {
            vm.startPrank(operator);
            stakingContract.addValidators(
                OPERATOR_INDEX,
                _limit,
                genBytes(48 * uint256(_limit)),
                genBytes(96 * uint256(_limit))
            );
            vm.stopPrank();
        }

        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSignature("LastEditAfterSnapshot()"));
        stakingContract.setOperatorLimit(OPERATOR_INDEX, _limit, block.number - 10);
        vm.stopPrank();
    }

    function testSetOperatorLimitUnauthorized() public {
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        stakingContract.setOperatorLimit(OPERATOR_INDEX, 10, block.number);
    }

    function testSetOperatorLimitTooHighUnauthorized() public {
        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSignature("OperatorLimitTooHigh(uint256,uint256)", 11, 10));
        stakingContract.setOperatorLimit(OPERATOR_INDEX, 11, block.number);
        vm.stopPrank();
    }

    function testSetOperatorLimitDeactivated(uint8 _limit) public {
        (, , uint256 limit, , , , ) = stakingContract.getOperator(OPERATOR_INDEX);
        assertEq(limit, 10);

        if (_limit > 0) {
            vm.startPrank(operator);
            stakingContract.addValidators(
                OPERATOR_INDEX,
                _limit,
                genBytes(48 * uint256(_limit)),
                genBytes(96 * uint256(_limit))
            );
            vm.stopPrank();
        }

        vm.startPrank(admin);
        stakingContract.deactivateOperator(OPERATOR_INDEX, operator);
        vm.expectRevert(abi.encodeWithSignature("Deactivated()"));
        stakingContract.setOperatorLimit(OPERATOR_INDEX, _limit, block.number);
        vm.stopPrank();
    }

    function testAddValidatorsOperator() public {
        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        ) = stakingContract.getOperator(OPERATOR_INDEX);
        assertEq(operatorAddress, operator);
        assertEq(feeRecipientAddress, feeRecipient);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 0);
        assertEq(available, 10);
        assert(deactivated == false);

        assertFalse(stakingContract.getEnabledFromPublicKeyRoot(sha256(abi.encodePacked(PUBKEY_2_1, bytes16(0)))));

        vm.startPrank(operator);
        vm.expectEmit(true, true, true, true);
        emit ValidatorKeysAdded(OPERATOR_INDEX, PUBLIC_KEYS_2, SIGNATURES_2);
        stakingContract.addValidators(OPERATOR_INDEX, 10, PUBLIC_KEYS_2, SIGNATURES_2);
        vm.stopPrank();

        assertTrue(stakingContract.getEnabledFromPublicKeyRoot(sha256(abi.encodePacked(PUBKEY_2_1, bytes16(0)))));

        (operatorAddress, feeRecipientAddress, limit, keys, funded, available, deactivated) = stakingContract
            .getOperator(OPERATOR_INDEX);
        assertEq(operatorAddress, operator);
        assertEq(feeRecipientAddress, feeRecipient);
        assertEq(limit, 10);
        assertEq(keys, 20);
        assertEq(funded, 0);
        assertEq(available, 10);
        assert(deactivated == false);

        vm.startPrank(admin);
        stakingContract.setOperatorLimit(OPERATOR_INDEX, 20, block.number);
        vm.stopPrank();

        (operatorAddress, feeRecipientAddress, limit, keys, funded, available, deactivated) = stakingContract
            .getOperator(OPERATOR_INDEX);

        assertEq(operatorAddress, operator);
        assertEq(feeRecipientAddress, feeRecipient);
        assertEq(limit, 20);
        assertEq(keys, 20);
        assertEq(funded, 0);
        assertEq(available, 20);
        assert(deactivated == false);
    }

    event DeactivatedOperator(uint256 _operatorIndex);
    event ActivatedOperator(uint256 _operatorIndex);

    function testAddValidatorsDeactivatedOperator() public {
        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        ) = stakingContract.getOperator(OPERATOR_INDEX);
        assertEq(operatorAddress, operator);
        assertEq(feeRecipientAddress, feeRecipient);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 0);
        assertEq(available, 10);
        assert(deactivated == false);

        vm.startPrank(admin);
        vm.expectEmit(true, true, true, true);
        emit DeactivatedOperator(OPERATOR_INDEX);
        stakingContract.deactivateOperator(OPERATOR_INDEX, address(1));
        vm.stopPrank();

        (operatorAddress, feeRecipient, limit, keys, funded, available, deactivated) = stakingContract.getOperator(
            OPERATOR_INDEX
        );
        assertEq(operatorAddress, operator);
        assertEq(feeRecipient, address(1));
        assertEq(limit, 0);
        assertEq(keys, 10);
        assertEq(funded, 0);
        assertEq(available, 0);
        assert(deactivated == true);

        vm.startPrank(operator);
        vm.expectRevert(abi.encodeWithSignature("Deactivated()"));
        stakingContract.addValidators(OPERATOR_INDEX, 10, PUBLIC_KEYS_2, SIGNATURES_2);
        vm.stopPrank();

        vm.startPrank(operator);
        uint256[] memory indexes = new uint256[](1);
        indexes[0] = 0;
        vm.expectRevert(abi.encodeWithSignature("Deactivated()"));
        stakingContract.removeValidators(OPERATOR_INDEX, indexes);
        vm.stopPrank();

        vm.startPrank(feeRecipient);
        vm.expectRevert(abi.encodeWithSignature("Deactivated()"));
        stakingContract.setOperatorAddresses(OPERATOR_INDEX, operator, feeRecipient);
        vm.stopPrank();

        vm.startPrank(admin);
        vm.expectEmit(true, true, true, true);
        emit ActivatedOperator(OPERATOR_INDEX);
        stakingContract.activateOperator(OPERATOR_INDEX, feeRecipient);
        vm.stopPrank();

        vm.startPrank(operator);
        stakingContract.addValidators(OPERATOR_INDEX, 10, PUBLIC_KEYS_2, SIGNATURES_2);
        vm.stopPrank();

        (operatorAddress, feeRecipient, limit, keys, funded, available, deactivated) = stakingContract.getOperator(
            OPERATOR_INDEX
        );

        assertEq(operatorAddress, operator);
        assertEq(feeRecipient, feeRecipient);
        assertEq(limit, 0);
        assertEq(keys, 20);
        assertEq(funded, 0);
        assertEq(available, 0);
        assert(deactivated == false);
    }

    function testAddValidatorsoperatorDuplicateKeys() public {
        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        ) = stakingContract.getOperator(OPERATOR_INDEX);
        assertEq(operatorAddress, operator);
        assertEq(feeRecipientAddress, feeRecipient);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 0);
        assertEq(available, 10);
        assert(deactivated == false);

        vm.startPrank(operator);
        stakingContract.addValidators(OPERATOR_INDEX, 10, PUBLIC_KEYS_2, SIGNATURES_2);
        vm.stopPrank();

        vm.startPrank(operator);
        vm.expectRevert(abi.encodeWithSignature("DuplicateValidatorKey(bytes)", PUBKEY_2_1));
        stakingContract.addValidators(OPERATOR_INDEX, 10, PUBLIC_KEYS_2, SIGNATURES_2);
        vm.stopPrank();
    }

    function testAddValidatorsInvalidPubKey() public {
        bytes memory corruptedPublicKeys = bytes.concat(PUBLIC_KEYS, hex"42");
        vm.startPrank(operator);
        vm.expectRevert(abi.encodeWithSignature("InvalidPublicKeys()"));
        stakingContract.addValidators(OPERATOR_INDEX, 10, corruptedPublicKeys, SIGNATURES);
        vm.stopPrank();
    }

    function testAddValidatorsInvalidSignature() public {
        bytes memory corruptedSignatures = bytes.concat(SIGNATURES, hex"42");
        vm.startPrank(operator);
        vm.expectRevert(abi.encodeWithSignature("InvalidSignatures()"));
        stakingContract.addValidators(OPERATOR_INDEX, 10, PUBLIC_KEYS, corruptedSignatures);
        vm.stopPrank();
    }

    function testAddValidatorsUnauthorized() public {
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        stakingContract.addValidators(OPERATOR_INDEX, 10, PUBLIC_KEYS, SIGNATURES);
    }

    function testRemoveValidatorsoperator() public {
        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        ) = stakingContract.getOperator(OPERATOR_INDEX);
        assertEq(operatorAddress, operator);
        assertEq(feeRecipientAddress, feeRecipient);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 0);
        assertEq(available, 10);
        assert(deactivated == false);

        uint256[] memory indexes = new uint256[](10);
        indexes[0] = 9;
        indexes[1] = 8;
        indexes[2] = 7;
        indexes[3] = 6;
        indexes[4] = 5;
        indexes[5] = 4;
        indexes[6] = 3;
        indexes[7] = 2;
        indexes[8] = 1;
        indexes[9] = 0;

        assertTrue(stakingContract.getEnabledFromPublicKeyRoot(sha256(abi.encodePacked(PUBKEY_10, bytes16(0)))));

        vm.startPrank(operator);
        vm.expectEmit(true, true, true, true);
        emit ValidatorKeyRemoved(OPERATOR_INDEX, PUBKEY_10);
        stakingContract.removeValidators(OPERATOR_INDEX, indexes);
        vm.stopPrank();

        assertFalse(stakingContract.getEnabledFromPublicKeyRoot(sha256(abi.encodePacked(PUBKEY_10, bytes16(0)))));

        (operatorAddress, feeRecipientAddress, limit, keys, funded, available, deactivated) = stakingContract
            .getOperator(OPERATOR_INDEX);

        assertEq(operatorAddress, operator);
        assertEq(limit, 0);
        assertEq(keys, 0);
        assertEq(funded, 0);
        assertEq(available, 0);
        assert(deactivated == false);
    }

    function testRemoveValidatorsDeactivatedoperator() public {
        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        ) = stakingContract.getOperator(OPERATOR_INDEX);
        assertEq(operatorAddress, operator);
        assertEq(feeRecipientAddress, feeRecipient);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 0);
        assertEq(available, 10);
        assert(deactivated == false);

        uint256[] memory indexes = new uint256[](10);
        indexes[0] = 9;
        indexes[1] = 8;
        indexes[2] = 7;
        indexes[3] = 6;
        indexes[4] = 5;
        indexes[5] = 4;
        indexes[6] = 3;
        indexes[7] = 2;
        indexes[8] = 1;
        indexes[9] = 0;

        vm.startPrank(admin);
        stakingContract.deactivateOperator(OPERATOR_INDEX, address(1));
        vm.stopPrank();

        vm.startPrank(operator);
        vm.expectRevert(abi.encodeWithSignature("Deactivated()"));
        stakingContract.removeValidators(OPERATOR_INDEX, indexes);
        vm.stopPrank();

        (operatorAddress, feeRecipientAddress, limit, keys, funded, available, deactivated) = stakingContract
            .getOperator(OPERATOR_INDEX);

        assertEq(operatorAddress, operator);
        assertEq(feeRecipientAddress, address(1));
        assertEq(limit, 0);
        assertEq(keys, 10);
        assertEq(funded, 0);
        assertEq(available, 0);
        assert(deactivated == true);

        vm.startPrank(admin);
        stakingContract.removeValidators(OPERATOR_INDEX, indexes);
        vm.stopPrank();

        (operatorAddress, feeRecipientAddress, limit, keys, funded, available, deactivated) = stakingContract
            .getOperator(OPERATOR_INDEX);

        assertEq(operatorAddress, operator);
        assertEq(feeRecipientAddress, address(1));
        assertEq(limit, 0);
        assertEq(keys, 0);
        assertEq(funded, 0);
        assertEq(available, 0);
        assert(deactivated == true);
    }

    function testRemoveValidatorsoperatorInvalidIndexes() public {
        uint256[] memory indexes = new uint256[](10);
        indexes[0] = 8;
        indexes[1] = 9;
        indexes[2] = 7;
        indexes[3] = 6;
        indexes[4] = 5;
        indexes[5] = 4;
        indexes[6] = 3;
        indexes[7] = 2;
        indexes[8] = 1;
        indexes[9] = 0;

        vm.startPrank(operator);
        vm.expectRevert(abi.encodeWithSignature("UnsortedIndexes()"));
        stakingContract.removeValidators(OPERATOR_INDEX, indexes);
        vm.stopPrank();
    }

    function testRemoveValidatorsoperatorUnauthorized() public {
        uint256[] memory indexes = new uint256[](10);
        indexes[0] = 9;
        indexes[1] = 8;
        indexes[2] = 7;
        indexes[3] = 6;
        indexes[4] = 5;
        indexes[5] = 4;
        indexes[6] = 3;
        indexes[7] = 2;
        indexes[8] = 1;
        indexes[9] = 0;

        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        stakingContract.removeValidators(OPERATOR_INDEX, indexes);
    }

    function testRemoveValidatorsWhileFunded(address user) public {
        vm.assume(user != address(depositContract));
        vm.deal(user, 32 * 1 ether);

        vm.startPrank(user);
        (bool _success, ) = address(stakingContract).call{value: 32 * 1 ether}("");
        assert(_success == true);
        vm.stopPrank();

        assertEq(user.balance, 0);

        uint256[] memory indexes = new uint256[](9);
        indexes[0] = 9;
        indexes[1] = 8;
        indexes[2] = 7;
        indexes[3] = 6;
        indexes[4] = 5;
        indexes[5] = 4;
        indexes[6] = 3;
        indexes[7] = 2;
        indexes[8] = 1;

        vm.startPrank(operator);
        stakingContract.removeValidators(OPERATOR_INDEX, indexes);
        vm.stopPrank();

        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        ) = stakingContract.getOperator(OPERATOR_INDEX);
        assertEq(operatorAddress, operator);
        assertEq(feeRecipientAddress, feeRecipient);
        assertEq(limit, 1);
        assertEq(keys, 1);
        assertEq(funded, 1);
        assertEq(available, 0);
        assert(deactivated == false);
    }

    function testRemoveFundedValidator(address user) public {
        vm.assume(user != address(depositContract));
        vm.deal(user, 32 * 3 ether);
        vm.roll(99999);

        vm.startPrank(user);
        (bool _success, ) = address(stakingContract).call{value: 32 * 3 ether}("");
        assert(_success == true);
        vm.stopPrank();

        assertEq(user.balance, 0);

        uint256[] memory indexes = new uint256[](10);
        indexes[0] = 9;
        indexes[1] = 8;
        indexes[2] = 7;
        indexes[3] = 6;
        indexes[4] = 5;
        indexes[5] = 4;
        indexes[6] = 3;
        indexes[7] = 2;
        indexes[8] = 1;
        indexes[9] = 0;

        vm.startPrank(operator);
        vm.expectRevert(abi.encodeWithSignature("FundedValidatorDeletionAttempt()"));
        stakingContract.removeValidators(OPERATOR_INDEX, indexes);
        vm.stopPrank();
    }

    event ChangedTreasury(address newTreasury);

    function testSetTreasury(address newTreasury) public {
        vm.startPrank(admin);
        vm.expectEmit(true, true, true, true);
        emit ChangedTreasury(newTreasury);
        stakingContract.setTreasury(newTreasury);
        vm.stopPrank();

        address gotTreasury = stakingContract.getTreasury();
        assertEq(newTreasury, gotTreasury);
    }

    function testSetTreasuryUnauthorized(address user) public {
        vm.assume(user != admin);
        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        stakingContract.setTreasury(user);
        vm.stopPrank();
    }
}

contract StakingContractInitializationTest is Test {
    address internal treasury;
    StakingContract internal stakingContract;
    DepositContractMock internal depositContract;

    address internal admin = address(1);

    bytes32 salt = bytes32(0);

    function setUp() public {
        treasury = address(99);
        stakingContract = new StakingContract();
        depositContract = new DepositContractMock();
    }

    function testFeeValidation() public {
        vm.expectRevert(abi.encodeWithSignature("InvalidFee()"));
        stakingContract.initialize_1(
            admin,
            address(treasury),
            address(depositContract),
            address(100),
            address(101),
            address(102),
            10001,
            2000,
            2000,
            5000
        );

        vm.expectRevert(abi.encodeWithSignature("InvalidFee()"));
        stakingContract.initialize_1(
            admin,
            address(treasury),
            address(depositContract),
            address(100),
            address(101),
            address(102),
            10000,
            10001,
            2000,
            5000
        );

        vm.expectRevert(abi.encodeWithSignature("InvalidFee()"));
        stakingContract.initialize_1(
            admin,
            address(treasury),
            address(depositContract),
            address(100),
            address(101),
            address(102),
            2000,
            5000,
            10001,
            5000
        );

        vm.expectRevert(abi.encodeWithSignature("InvalidFee()"));
        stakingContract.initialize_1(
            admin,
            address(treasury),
            address(depositContract),
            address(100),
            address(101),
            address(102),
            2000,
            5000,
            2000,
            10001
        );
    }

    event NewOperator(address operatorAddress, address feeRecipientAddress, uint256 index);

    function testAddOperator(address newOperator, address newOperatorFeeRecipient) public {
        stakingContract.initialize_1(
            admin,
            address(treasury),
            address(depositContract),
            address(100),
            address(101),
            address(102),
            1000,
            2000,
            2000,
            5000
        );

        vm.startPrank(admin);
        vm.expectEmit(true, true, true, true);
        emit NewOperator(newOperator, newOperatorFeeRecipient, 0);
        stakingContract.addOperator(newOperator, newOperatorFeeRecipient);
        vm.stopPrank();

        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        ) = stakingContract.getOperator(OPERATOR_INDEX);
        assertEq(operatorAddress, newOperator);
        assertEq(feeRecipientAddress, newOperatorFeeRecipient);
        assertEq(limit, 0);
        assertEq(keys, 0);
        assertEq(funded, 0);
        assertEq(available, 0);
        assert(deactivated == false);
    }
}

contract StakingContractOperatorTest is Test {
    address internal treasury;
    StakingContract internal stakingContract;
    DepositContractMock internal depositContract;

    address internal admin = address(1);

    bytes32 salt = bytes32(0);

    function setUp() public {
        treasury = address(99);
        stakingContract = new StakingContract();
        depositContract = new DepositContractMock();
        stakingContract.initialize_1(
            admin,
            address(treasury),
            address(depositContract),
            address(100),
            address(101),
            address(102),
            1000,
            2000,
            2000,
            5000
        );
    }

    function testAddOperatorLimitReached(address newOperator, address newOperatorFeeRecipient) public {
        vm.startPrank(admin);
        stakingContract.addOperator(newOperator, newOperatorFeeRecipient);
        address operatorZero = newOperator;

        vm.stopPrank();
        vm.startPrank(operatorZero);
        stakingContract.addValidators(OPERATOR_INDEX, 10, PUBLIC_KEYS, SIGNATURES);
        vm.stopPrank();
        vm.startPrank(admin);
        stakingContract.setOperatorLimit(OPERATOR_INDEX, 10, block.number);
        vm.stopPrank();

        vm.deal(address(this), 32 ether);
        stakingContract.deposit{value: 32 ether}();

        vm.startPrank(admin);
        newOperator = makeAddr("newOperator2");
        newOperatorFeeRecipient = makeAddr("newOperatorFeeRecipient2");
        vm.expectRevert(abi.encodeWithSignature("MaximumOperatorCountAlreadyReached()"));
        stakingContract.addOperator(newOperator, newOperatorFeeRecipient);
        vm.stopPrank();
    }
}

contract StakingContractDistributionTest is Test {
    address internal treasury;
    StakingContract internal stakingContract;
    DepositContractMock internal depositContract;

    address internal admin = address(1);
    address internal bob = address(2);
    address internal alice = address(3);
    address[] internal operators;
    bytes32 salt = bytes32(0);

    function setUp() public {
        treasury = address(99);
        stakingContract = new StakingContract();
        depositContract = new DepositContractMock();
        stakingContract.initialize_1(
            admin,
            address(treasury),
            address(depositContract),
            address(100),
            address(101),
            address(102),
            1000,
            2000,
            2000,
            5000
        );
    }

    function genBytes(uint256 len) internal returns (bytes memory) {
        bytes memory res = "";
        while (res.length < len) {
            salt = keccak256(abi.encodePacked(salt));
            if (len - res.length >= 32) {
                res = BytesLib.concat(res, abi.encode(salt));
            } else {
                res = BytesLib.concat(res, BytesLib.slice(abi.encode(salt), 0, len - res.length));
            }
        }
        return res;
    }

    function testDistribution(uint8 keyPerOperator) public {
        keyPerOperator = keyPerOperator % 50;

        uint256 newOps = 1;

        if (keyPerOperator == 0) {
            keyPerOperator = 3;
        }

        uint256 depositCount = uint256(keyPerOperator) / 2;

        vm.startPrank(admin);
        address newOperator = makeAddr("newOp");
        address newOperatorFeeRecipient = makeAddr("newOpFeRe");

        stakingContract.addOperator(newOperator, newOperatorFeeRecipient);
        operators.push(newOperator);
        vm.stopPrank();
        vm.startPrank(newOperator);
        bytes memory publicKeys = genBytes(uint256(keyPerOperator) * 48);
        bytes memory signatures = genBytes(uint256(keyPerOperator) * 96);
        stakingContract.addValidators(OPERATOR_INDEX, keyPerOperator, publicKeys, signatures);
        vm.stopPrank();
        vm.startPrank(admin);
        stakingContract.setOperatorLimit(OPERATOR_INDEX, keyPerOperator, block.number);
        vm.stopPrank();

        for (uint256 i; i < depositCount; ) {
            // +1 To prevent underflow.
            vm.roll(i + 1);
            uint256 availableKeys = stakingContract.getAvailableValidatorCount();
            salt = keccak256(abi.encode(salt));
            uint256 newDeposits = (uint8(salt[0]) % 31) + 1;
            if (i + newDeposits > depositCount) {
                newDeposits = (depositCount - i);
            }
            vm.deal(bob, newDeposits * 32 ether);
            vm.startPrank(bob);
            stakingContract.deposit{value: newDeposits * 32 ether}();
            vm.stopPrank();
            i += newDeposits;
            assert(stakingContract.getAvailableValidatorCount() == availableKeys - newDeposits);
        }

        uint256 sum;
        uint256 availableSum;

        for (uint256 i; i < newOps; ++i) {
            (, , , , uint256 funded, uint256 available, bool deactivated) = stakingContract.getOperator(i);
            sum += funded;
            availableSum += available;
            assert(deactivated == false);
        }

        assert(depositCount == sum);
        assert(availableSum == stakingContract.getAvailableValidatorCount());
        assert(address(depositContract).balance == depositCount * 32 ether);
    }
}

contract StakingContractOneValidatorTest is Test {
    StakingContract internal stakingContract;
    DepositContractMock internal depositContract;

    address internal proxyAdmin;
    address internal admin;
    address internal bob;
    address internal alice;
    address internal operator;
    address internal feeRecipient;
    address internal treasury;

    ExecutionLayerFeeDispatcher internal eld;
    ConsensusLayerFeeDispatcher internal cld;
    FeeRecipient internal feeRecipientImpl;

    function setUp() public {
        proxyAdmin = makeAddr("proxyAdmin");
        admin = makeAddr("admin");
        bob = makeAddr("bob");
        alice = makeAddr("alice");
        operator = makeAddr("operator");
        feeRecipient = makeAddr("feeRecipient");
        treasury = makeAddr("treasury");

        stakingContract = new StakingContract();
        depositContract = new DepositContractMock();
        feeRecipientImpl = new FeeRecipient();

        address eldImpl = address(new ExecutionLayerFeeDispatcher(1));
        address cldImpl = address(new ConsensusLayerFeeDispatcher(1));

        eld = ExecutionLayerFeeDispatcher(
            payable(
                address(new TUPProxy(eldImpl, proxyAdmin, abi.encodeWithSignature("initELD(address)", stakingContract)))
            )
        );

        cld = ConsensusLayerFeeDispatcher(
            payable(
                address(new TUPProxy(cldImpl, proxyAdmin, abi.encodeWithSignature("initCLD(address)", stakingContract)))
            )
        );

        stakingContract.initialize_1(
            admin,
            address(treasury),
            address(depositContract),
            address(eld),
            address(cld),
            address(feeRecipientImpl),
            1000,
            2000,
            2000,
            5000
        );

        vm.startPrank(admin);
        stakingContract.addOperator(operator, feeRecipient);
        vm.stopPrank();

        {
            vm.startPrank(operator);
            stakingContract.addValidators(OPERATOR_INDEX, 10, PUBLIC_KEYS, SIGNATURES);
            vm.stopPrank();
        }

        {
            vm.startPrank(admin);
            stakingContract.setOperatorLimit(OPERATOR_INDEX, 10, block.number);
            vm.stopPrank();
        }
    }

    event Deposit(address indexed caller, address indexed withdrawer, bytes publicKey, bytes signature);
    event DepositEvent(bytes pubkey, bytes withdrawal_credentials, bytes amount, bytes signature, bytes index);

    function assumeAddress(address user) public view {
        vm.assume(user != proxyAdmin && user != address(depositContract));
    }

    function testExplicitDepositOneValidatorCheckDepositEvent(address user) public {
        assumeAddress(user);
        vm.deal(user, 32 ether);

        vm.startPrank(user);
        bytes memory expectedWithdrawalCredentials = abi.encodePacked(
            bytes32(
                uint256(uint160(stakingContract.getCLFeeRecipient(PUBKEY_1))) +
                    0x0100000000000000000000000000000000000000000000000000000000000000
            )
        );
        vm.expectEmit(true, true, true, true);
        emit DepositEvent(
            PUBKEY_1,
            expectedWithdrawalCredentials,
            hex"0040597307000000",
            SIGNATURE_1,
            hex"0000000000000000"
        );
        stakingContract.deposit{value: 32 ether}();
        vm.stopPrank();

        assertEq(user.balance, 0);

        (, , uint256 limit, uint256 keys, uint256 funded, uint256 available, bool deactivated) = stakingContract
            .getOperator(OPERATOR_INDEX);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 1);
        assertEq(available, 9);
        assert(deactivated == false);
    }

    function testExplicitDepositOneValidator(address user) public {
        assumeAddress(user);
        vm.deal(user, 32 ether);

        vm.startPrank(user);
        stakingContract.deposit{value: 32 ether}();
        vm.stopPrank();

        assertEq(user.balance, 0);

        (, , uint256 limit, uint256 keys, uint256 funded, uint256 available, bool deactivated) = stakingContract
            .getOperator(OPERATOR_INDEX);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 1);
        assertEq(available, 9);
        assert(deactivated == false);
    }

    function testExplicitDepositTwoValidators(address user) public {
        assumeAddress(user);
        vm.deal(user, 32 * 2 ether);

        vm.startPrank(user);
        vm.expectEmit(true, true, true, true);
        emit Deposit(user, user, PUBKEY_2, SIGNATURE_2);
        stakingContract.deposit{value: 32 * 2 ether}();
        vm.stopPrank();

        assertEq(user.balance, 0);

        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        ) = stakingContract.getOperator(OPERATOR_INDEX);
        assertEq(operatorAddress, operator);
        assertEq(feeRecipientAddress, feeRecipient);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 2);
        assertEq(available, 8);
        assert(deactivated == false);
    }

    function testExplicitDepositAllValidators(address user) public {
        assumeAddress(user);
        vm.deal(user, 32 * 10 ether);

        vm.startPrank(user);
        stakingContract.deposit{value: 32 * 10 ether}();
        vm.stopPrank();

        assertEq(user.balance, 0);

        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        ) = stakingContract.getOperator(OPERATOR_INDEX);
        assertEq(operatorAddress, operator);
        assertEq(feeRecipientAddress, feeRecipient);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 10);
        assertEq(available, 0);
        assert(deactivated == false);
    }

    function testExplicitDepositNotEnough(address user) public {
        assumeAddress(user);
        vm.deal(user, 32 * 11 ether);

        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("NotEnoughValidators()"));
        stakingContract.deposit{value: 32 * 11 ether}();
        vm.stopPrank();
    }

    function testExplicitDepositNotEnoughAfterFilled(address user) public {
        assumeAddress(user);
        vm.deal(user, 32 * 11 ether);

        vm.startPrank(user);
        stakingContract.deposit{value: 32 * 10 ether}();
        vm.stopPrank();
        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("NotEnoughValidators()"));
        stakingContract.deposit{value: 32 ether}();
        vm.stopPrank();
    }

    function testExplicitDepositInvalidAmount(address user) public {
        assumeAddress(user);
        vm.deal(user, 31.9 ether);

        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("InvalidDepositValue()"));
        stakingContract.deposit{value: 31.9 ether}();
        vm.stopPrank();
    }

    function testImplicitDepositOneValidator(address user) public {
        assumeAddress(user);
        vm.deal(user, 32 ether);

        vm.startPrank(user);
        (bool _success, ) = address(stakingContract).call{value: 32 ether}("");
        assert(_success == true);
        vm.stopPrank();

        assertEq(user.balance, 0);

        (, , uint256 limit, uint256 keys, uint256 funded, uint256 available, bool deactivated) = stakingContract
            .getOperator(OPERATOR_INDEX);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 1);
        assertEq(available, 9);
        assert(deactivated == false);
    }

    function testImplicitDepositTwoValidators(address user) public {
        assumeAddress(user);
        vm.deal(user, 32 * 2 ether);

        vm.startPrank(user);
        vm.expectEmit(true, true, true, true);
        emit Deposit(user, user, PUBKEY_2, SIGNATURE_2);
        (bool _success, ) = address(stakingContract).call{value: 32 * 2 ether}("");
        assert(_success == true);
        vm.stopPrank();

        assertEq(user.balance, 0);

        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        ) = stakingContract.getOperator(OPERATOR_INDEX);
        assertEq(operatorAddress, operator);
        assertEq(feeRecipientAddress, feeRecipient);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 2);
        assertEq(available, 8);
        assert(deactivated == false);
    }

    function testImplicitDepositAllValidators(address user) public {
        assumeAddress(user);
        vm.deal(user, 32 * 10 ether);

        vm.startPrank(user);
        (bool _success, ) = address(stakingContract).call{value: 32 * 10 ether}("");
        assert(_success == true);
        vm.stopPrank();

        assertEq(user.balance, 0);

        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        ) = stakingContract.getOperator(OPERATOR_INDEX);
        assertEq(operatorAddress, operator);
        assertEq(feeRecipientAddress, feeRecipient);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 10);
        assertEq(available, 0);
        assert(deactivated == false);
    }

    function testImplicitDepositNotEnough(address user) public {
        assumeAddress(user);
        vm.deal(user, 32 * 11 ether);

        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("NotEnoughValidators()"));
        (bool _success, ) = address(stakingContract).call{value: 32 * 11 ether}("");
        assert(_success == true);
        vm.stopPrank();
    }

    function testImplicitDepositNotEnoughAfterFilled(address user) public {
        assumeAddress(user);
        vm.deal(user, 32 * 11 ether);

        vm.startPrank(user);
        (bool _success, ) = address(stakingContract).call{value: 32 * 10 ether}("");
        assert(_success == true);
        vm.stopPrank();
        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("NotEnoughValidators()"));
        (_success, ) = address(stakingContract).call{value: 32 ether}("");
        assert(_success == true);
        vm.stopPrank();
    }

    function testImplicitDepositInvalidAmount(address user) public {
        assumeAddress(user);
        vm.deal(user, 31.9 ether);

        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("InvalidDepositValue()"));
        (bool _success, ) = address(stakingContract).call{value: 31.9 ether}("");
        assert(_success == true);
        vm.stopPrank();
    }

    event ChangedOperatorFee(uint256 newOperatorFee);

    function testEditOperatorFee() public {
        assert(stakingContract.getOperatorFee() == 2000);
        vm.startPrank(admin);
        vm.expectEmit(true, true, true, true);
        emit ChangedOperatorFee(3000);
        stakingContract.setOperatorFee(3000);
        vm.stopPrank();
        assert(stakingContract.getOperatorFee() == 3000);
    }

    function testEditOperatorFee_OverLimit() public {
        assert(stakingContract.getOperatorFee() == 2000);
        vm.expectRevert(abi.encodeWithSignature("InvalidFee()"));
        vm.startPrank(admin);
        stakingContract.setOperatorFee(5001);
        vm.stopPrank();
        assert(stakingContract.getOperatorFee() == 2000);
    }

    event ChangedGlobalFee(uint256 newGlobalFee);

    function testEditGlobalFee() public {
        assert(stakingContract.getGlobalFee() == 1000);
        vm.startPrank(admin);
        vm.expectEmit(true, true, true, true);
        emit ChangedGlobalFee(2000);
        stakingContract.setGlobalFee(2000);
        vm.stopPrank();
        assert(stakingContract.getGlobalFee() == 2000);
    }

    function testEditGlobalFee_OverLimit() public {
        assert(stakingContract.getGlobalFee() == 1000);
        vm.expectRevert(abi.encodeWithSignature("InvalidFee()"));
        vm.startPrank(admin);
        stakingContract.setGlobalFee(2001);
        vm.stopPrank();
        assert(stakingContract.getGlobalFee() == 1000);
    }

    event ChangedDepositsStopped(bool isStopped);

    function testSetDepositStopped() public {
        address staker = makeAddr("staker");
        vm.deal(staker, 64 ether);
        assert(stakingContract.getDepositsStopped() == false);
        vm.prank(staker);
        stakingContract.deposit{value: 32 ether}();

        vm.expectEmit(true, true, true, true);
        emit ChangedDepositsStopped(true);
        vm.startPrank(admin);
        stakingContract.setDepositsStopped(true);
        vm.stopPrank();

        assert(stakingContract.getDepositsStopped() == true);
        vm.expectRevert(abi.encodeWithSignature("DepositsStopped()"));
        vm.prank(staker);
        stakingContract.deposit{value: 32 ether}();
    }

    function testSetDepositStopped_asRandom() public {
        assert(stakingContract.getDepositsStopped() == false);
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        vm.startPrank(address(0x31337));
        stakingContract.setDepositsStopped(true);
        vm.stopPrank();
    }

    function testFeeRecipients() public {
        bytes memory publicKey = PUBKEY_1;
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        address _elfr = stakingContract.getELFeeRecipient(publicKey);
        address _clfr = stakingContract.getCLFeeRecipient(publicKey);
        assert(_elfr != _clfr);
        vm.stopPrank();
    }

    function testWithdrawELFees() public {
        bytes memory publicKey = PUBKEY_1;
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(publicKey);
        assert(elfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0);
        vm.deal(address(elfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.withdrawELFee(publicKey);
        assert(elfrBob.code.length != 0);
        assert(bob.balance == 0.9 ether);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0.02 ether);
        assert(address(treasury).balance == 0.08 ether);
    }

    function testWithdrawELFees_asAdmin() public {
        bytes memory publicKey = PUBKEY_1;
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(publicKey);
        assert(elfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0);
        vm.deal(address(elfrBob), 1 ether);
        vm.prank(admin);
        stakingContract.withdrawELFee(publicKey);
        assert(elfrBob.code.length != 0);
        assert(bob.balance == 0.9 ether);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0.02 ether);
        assert(address(treasury).balance == 0.08 ether);
    }

    function testWithdrawELFees_asRandom() public {
        bytes memory publicKey = PUBKEY_1;
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(publicKey);
        assert(elfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0);
        vm.deal(address(elfrBob), 1 ether);
        vm.expectRevert(abi.encodeWithSignature("InvalidWithdrawer()"));
        vm.prank(address(0xdede));
        stakingContract.withdrawELFee(publicKey);
    }

    function testWithdrawELFeesEditedOperatorFee() public {
        vm.startPrank(admin);
        stakingContract.setOperatorFee(5000);
        vm.stopPrank();
        bytes memory publicKey = PUBKEY_1;
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(publicKey);
        assert(elfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0);
        assert(address(treasury).balance == 0);
        vm.deal(address(elfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.withdrawELFee(publicKey);
        assert(elfrBob.code.length != 0);
        assert(bob.balance == 0.9 ether);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0.05 ether);
        assert(address(treasury).balance == 0.05 ether);
    }

    function testWithdrawELFeesAlreadyDeployed() public {
        bytes memory publicKey = PUBKEY_1;
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(publicKey);
        assert(elfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0);
        vm.deal(address(elfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.withdrawELFee(publicKey);
        assert(elfrBob.code.length != 0);
        assert(bob.balance == 0.9 ether);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0.02 ether);
        assert(address(treasury).balance == 0.08 ether);
        vm.deal(address(elfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.withdrawELFee(publicKey);
        assert(bob.balance == 1.8 ether);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0.04 ether);
        assert(address(treasury).balance == 0.16 ether);
    }

    function testWithdrawELFeesEmptyWithdrawal() public {
        bytes memory publicKey = PUBKEY_1;
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.expectRevert(abi.encodeWithSignature("ZeroBalanceWithdrawal()"));
        stakingContract.withdrawELFee(publicKey);
        vm.stopPrank();
    }

    function testWithdrawCLFeesExitedValidator() public {
        bytes memory publicKey = PUBKEY_1;
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(address(treasury).balance == 0 ether);
        assert(feeRecipient.balance == 0);
        vm.deal(address(clfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.requestValidatorsExit(publicKey);
        vm.deal(address(clfrBob), 33 ether);
        vm.prank(bob);
        stakingContract.withdrawCLFee(publicKey);
        assert(clfrBob.code.length != 0);
        assertApproxEqAbs(bob.balance, 32.90 ether, 10**5);
        assertEq(operator.balance, 0);
        assertApproxEqAbs(address(treasury).balance, 0.08 ether, 10**5);
        assertApproxEqAbs(feeRecipient.balance, 0.02 ether, 10**5);
    }

    function testWithdrawCLFeesEditedOperatorFee() public {
        vm.startPrank(admin);
        stakingContract.setOperatorFee(5000);
        vm.stopPrank();
        bytes memory publicKey = PUBKEY_1;
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0);
        assert(address(treasury).balance == 0);
        vm.deal(address(clfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.requestValidatorsExit(publicKey);
        vm.deal(address(clfrBob), 33 ether);
        vm.prank(bob);
        stakingContract.withdrawCLFee(publicKey);
        assert(clfrBob.code.length != 0);
        assertApproxEqAbs(bob.balance, 32.90 ether, 10**6);
        assertApproxEqAbs(address(treasury).balance, 0.05 ether, 10**6);
        assertEq(operator.balance, 0);
        assertApproxEqAbs(feeRecipient.balance, 0.05 ether, 10**6);
    }

    function testWithdrawCLFeesSkimmedValidator() public {
        bytes memory publicKey = PUBKEY_1;
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0);
        assert(address(treasury).balance == 0);
        vm.deal(address(clfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.withdrawCLFee(publicKey);
        assert(clfrBob.code.length != 0);
        assertApproxEqAbs(bob.balance, 0.90 ether, 10**6);
        assertApproxEqAbs(address(treasury).balance, 0.08 ether, 10**6);
        assertEq(operator.balance, 0);
        assertApproxEqAbs(feeRecipient.balance, 0.02 ether, 10**6);
    }

    function testWithdrawCLFeesSkimmedLuckyValidator() public {
        bytes memory publicKey = PUBKEY_1;
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0);
        assert(address(treasury).balance == 0);
        vm.deal(address(clfrBob), 2 ether);
        vm.prank(bob);
        stakingContract.withdrawCLFee(publicKey);
        assert(clfrBob.code.length != 0);
        assertApproxEqAbs(bob.balance, 1.8 ether, 10**6);
        assertApproxEqAbs(address(treasury).balance, 0.16 ether, 10**6);
        assertEq(operator.balance, 0);
        assertApproxEqAbs(feeRecipient.balance, 0.04 ether, 10**6);
    }

    function testWithdrawCLFeesSlashedValidator() public {
        bytes memory publicKey = PUBKEY_1;
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        vm.deal(address(clfrBob), 1 ether); // 1 ETH skimmed
        vm.deal(address(clfrBob), 32 ether); // 31 ETH forced exit after slashing, exit not requested
        vm.prank(bob);
        stakingContract.withdrawCLFee(publicKey);
        assert(clfrBob.code.length != 0);
        // In this case bob would be manually rebated, including the commission charged on it's principal
        assertApproxEqAbs(bob.balance, 28.8 ether, 1);
        assertApproxEqAbs(address(treasury).balance, 2.56 ether, 10**6);
        assertApproxEqAbs(feeRecipient.balance, 0.64 ether, 10**6);
    }

    function testWithdrawCLFeesAlreadyDeployed() public {
        bytes memory publicKey = PUBKEY_1;
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0);

        vm.deal(address(clfrBob), 1 ether);
        vm.prank(bob);

        stakingContract.withdrawCLFee(publicKey);

        assert(clfrBob.code.length != 0);
        assertApproxEqAbs(bob.balance, 0.90 ether, 10**6);
        assertApproxEqAbs(address(treasury).balance, 0.08 ether, 10**6);
        assertEq(operator.balance, 0);
        assertApproxEqAbs(feeRecipient.balance, 0.02 ether, 10**6);

        vm.deal(address(clfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.requestValidatorsExit(publicKey);
        vm.deal(address(clfrBob), 33 ether);
        vm.prank(bob);
        stakingContract.withdrawCLFee(publicKey);

        assertApproxEqAbs(bob.balance, 33.80 ether, 10**6);
        assertApproxEqAbs(address(treasury).balance, 0.16 ether, 10**6);
        assertEq(operator.balance, 0);
        assertApproxEqAbs(feeRecipient.balance, 0.04 ether, 10**6);
    }

    function testWithdrawCLFeesEmptyWithdrawal() public {
        bytes memory publicKey = PUBKEY_1;
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.expectRevert(abi.encodeWithSignature("ZeroBalanceWithdrawal()"));
        stakingContract.withdrawCLFee(publicKey);
        vm.stopPrank();
    }

    function testWithdrawAllFees() public {
        bytes memory publicKey = PUBKEY_1;
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();

        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);

        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0);
        assert(address(treasury).balance == 0);

        vm.deal(address(clfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.requestValidatorsExit(publicKey);
        vm.deal(address(clfrBob), 33 ether);

        address elfrBob = stakingContract.getELFeeRecipient(publicKey);
        assert(elfrBob.code.length == 0);
        vm.deal(address(elfrBob), 1 ether);

        vm.prank(bob);
        stakingContract.withdraw(publicKey);

        assertApproxEqAbs(bob.balance, 33.80 ether, 10**6);
        assertApproxEqAbs(address(treasury).balance, 0.16 ether, 10**6);
        assertEq(operator.balance, 0);
        assertApproxEqAbs(feeRecipient.balance, 0.04 ether, 10**6);
    }
}

contract SanctionsOracle {
    mapping(address => bool) sanctionsMap;

    function isSanctioned(address user) public view returns (bool) {
        return sanctionsMap[user];
    }

    function setSanction(address user, bool status) public {
        sanctionsMap[user] = status;
    }
}

contract StakingContractBehindProxyTest is Test {
    StakingContract internal stakingContract;
    DepositContractMock internal depositContract;

    address internal proxyAdmin;
    address internal admin;
    address internal bob;
    address internal alice;
    address internal operator;
    address internal feeRecipient;
    address internal treasury;

    ExecutionLayerFeeDispatcher internal eld;
    ConsensusLayerFeeDispatcher internal cld;
    FeeRecipient internal feeRecipientImpl;

    SanctionsOracle oracle;

    event ExitRequest(address caller, bytes pubkey);

    function setUp() public {
        proxyAdmin = makeAddr("proxyAdmin");
        admin = makeAddr("admin");
        bob = makeAddr("bob");
        alice = makeAddr("alice");
        operator = makeAddr("operator");
        feeRecipient = makeAddr("feeRecipient");
        treasury = makeAddr("treasury");

        depositContract = new DepositContractMock();
        feeRecipientImpl = new FeeRecipient();

        address eldImpl = address(new ExecutionLayerFeeDispatcher(1));
        address cldImpl = address(new ConsensusLayerFeeDispatcher(1));
        address stakingContractImpl = address(new StakingContract());

        stakingContract = StakingContract(payable(address(new TUPProxy(stakingContractImpl, proxyAdmin, ""))));

        eld = ExecutionLayerFeeDispatcher(
            payable(
                address(new TUPProxy(eldImpl, proxyAdmin, abi.encodeWithSignature("initELD(address)", stakingContract)))
            )
        );

        cld = ConsensusLayerFeeDispatcher(
            payable(
                address(new TUPProxy(cldImpl, proxyAdmin, abi.encodeWithSignature("initCLD(address)", stakingContract)))
            )
        );

        stakingContract.initialize_1(
            admin,
            address(treasury),
            address(depositContract),
            address(eld),
            address(cld),
            address(feeRecipientImpl),
            1000,
            2000,
            2000,
            5000
        );

        vm.startPrank(admin);
        stakingContract.addOperator(operator, feeRecipient);
        vm.stopPrank();

        {
            vm.startPrank(operator);
            stakingContract.addValidators(OPERATOR_INDEX, 10, PUBLIC_KEYS, SIGNATURES);
            vm.stopPrank();
        }

        {
            vm.startPrank(admin);
            stakingContract.setOperatorLimit(OPERATOR_INDEX, 10, block.number);
            vm.stopPrank();
        }

        oracle = new SanctionsOracle();
    }

    event Deposit(address indexed caller, address indexed withdrawer, bytes publicKey, bytes signature);
    event DepositEvent(bytes pubkey, bytes withdrawal_credentials, bytes amount, bytes signature, bytes index);

    function assumeAddress(address user) public view {
        vm.assume(user != proxyAdmin && user != address(depositContract));
    }

    function testExplicitDepositOneValidatorCheckDepositEvent(address user) public {
        assumeAddress(user);
        vm.deal(user, 32 ether);

        vm.startPrank(user);
        bytes memory expectedWithdrawalCredentials = abi.encodePacked(
            bytes32(
                uint256(uint160(stakingContract.getCLFeeRecipient(PUBKEY_1))) +
                    0x0100000000000000000000000000000000000000000000000000000000000000
            )
        );
        vm.expectEmit(true, true, true, true);
        emit DepositEvent(
            PUBKEY_1,
            expectedWithdrawalCredentials,
            hex"0040597307000000",
            SIGNATURE_1,
            hex"0000000000000000"
        );
        stakingContract.deposit{value: 32 ether}();
        vm.stopPrank();

        assertEq(user.balance, 0);

        (, , uint256 limit, uint256 keys, uint256 funded, uint256 available, bool deactivated) = stakingContract
            .getOperator(OPERATOR_INDEX);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 1);
        assertEq(available, 9);
        assert(deactivated == false);
    }

    function testExplicitDepositOneValidator(address user) public {
        assumeAddress(user);
        vm.deal(user, 32 ether);

        vm.startPrank(user);
        stakingContract.deposit{value: 32 ether}();
        vm.stopPrank();

        assertEq(user.balance, 0);

        (, , uint256 limit, uint256 keys, uint256 funded, uint256 available, bool deactivated) = stakingContract
            .getOperator(OPERATOR_INDEX);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 1);
        assertEq(available, 9);
        assert(deactivated == false);
    }

    event NewSanctionsOracle(address);

    function test_setSanctionsOracle() public {
        assertEq(stakingContract.getSanctionsOracle(), address(0));
        vm.startPrank(admin);
        vm.expectEmit(true, true, true, true);
        emit NewSanctionsOracle(address(oracle));
        stakingContract.setSanctionsOracle(address(oracle));
        vm.stopPrank();
        assertEq(stakingContract.getSanctionsOracle(), address(oracle));
    }

    function test_deposit_withsanctions_senderSanctioned(address user) public {
        assumeAddress(user);
        oracle.setSanction(user, true);

        vm.prank(admin);
        stakingContract.setSanctionsOracle(address(oracle));

        vm.deal(user, 32 ether);

        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("AddressSanctioned(address)", user));
        stakingContract.deposit{value: 32 ether}();
        vm.stopPrank();
    }

    function test_deposit_withSanctions_SenderClear(address user) public {
        assumeAddress(user);

        vm.prank(admin);
        stakingContract.setSanctionsOracle(address(oracle));

        vm.deal(user, 32 ether);

        vm.startPrank(user);
        stakingContract.deposit{value: 32 ether}();
        vm.stopPrank();
        assertEq(user, stakingContract.getWithdrawer(PUBKEY_1));
    }

    function test_deposit_BlockedUser(address user) public {
        assumeAddress(user);

        vm.prank(admin);
        stakingContract.blockAccount(user, "");

        vm.deal(user, 32 ether);

        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("AddressBlocked(address)", user));
        stakingContract.deposit{value: 32 ether}();
        vm.stopPrank();
    }

    function testExplicitDepositTwoValidators(address user) public {
        assumeAddress(user);

        vm.deal(user, 32 * 2 ether);

        vm.startPrank(user);
        vm.expectEmit(true, true, true, true);
        emit Deposit(user, user, PUBKEY_2, SIGNATURE_2);
        stakingContract.deposit{value: 32 * 2 ether}();
        vm.stopPrank();

        assertEq(user.balance, 0);

        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        ) = stakingContract.getOperator(OPERATOR_INDEX);
        assertEq(operatorAddress, operator);
        assertEq(feeRecipientAddress, feeRecipient);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 2);
        assertEq(available, 8);
        assert(deactivated == false);
    }

    function testExplicitDepositAllValidators(address user) public {
        assumeAddress(user);

        vm.deal(user, 32 * 10 ether);

        vm.startPrank(user);
        stakingContract.deposit{value: 32 * 10 ether}();
        vm.stopPrank();

        assertEq(user.balance, 0);

        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        ) = stakingContract.getOperator(OPERATOR_INDEX);
        assertEq(operatorAddress, operator);
        assertEq(feeRecipientAddress, feeRecipient);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 10);
        assertEq(available, 0);
        assert(deactivated == false);
    }

    function testExplicitDepositNotEnough(address user) public {
        assumeAddress(user);

        vm.deal(user, 32 * 11 ether);

        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("NotEnoughValidators()"));
        stakingContract.deposit{value: 32 * 11 ether}();
        vm.stopPrank();
    }

    function testExplicitDepositNotEnoughAfterFilled(address user) public {
        assumeAddress(user);

        vm.deal(user, 32 * 11 ether);

        vm.startPrank(user);
        stakingContract.deposit{value: 32 * 10 ether}();
        vm.stopPrank();
        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("NotEnoughValidators()"));
        stakingContract.deposit{value: 32 ether}();
        vm.stopPrank();
    }

    function testExplicitDepositInvalidAmount(address user) public {
        assumeAddress(user);

        vm.deal(user, 31.9 ether);

        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("InvalidDepositValue()"));
        stakingContract.deposit{value: 31.9 ether}();
        vm.stopPrank();
    }

    function testImplicitDepositOneValidator(address user) public {
        assumeAddress(user);

        vm.deal(user, 32 ether);

        vm.startPrank(user);
        (bool _success, ) = address(stakingContract).call{value: 32 ether}("");
        assert(_success == true);
        vm.stopPrank();

        assertEq(user.balance, 0);

        (, , uint256 limit, uint256 keys, uint256 funded, uint256 available, bool deactivated) = stakingContract
            .getOperator(OPERATOR_INDEX);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 1);
        assertEq(available, 9);
        assert(deactivated == false);
    }

    function testImplicitDepositTwoValidators(address user) public {
        assumeAddress(user);

        vm.deal(user, 32 * 2 ether);

        vm.startPrank(user);
        vm.expectEmit(true, true, true, true);
        emit Deposit(user, user, PUBKEY_2, SIGNATURE_2);
        (bool _success, ) = address(stakingContract).call{value: 32 * 2 ether}("");
        assert(_success == true);
        vm.stopPrank();

        assertEq(user.balance, 0);

        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        ) = stakingContract.getOperator(OPERATOR_INDEX);
        assertEq(operatorAddress, operator);
        assertEq(feeRecipientAddress, feeRecipient);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 2);
        assertEq(available, 8);
        assert(deactivated == false);
    }

    function testImplicitDepositAllValidators(address user) public {
        assumeAddress(user);

        vm.deal(user, 32 * 10 ether);

        vm.startPrank(user);
        (bool _success, ) = address(stakingContract).call{value: 32 * 10 ether}("");
        assert(_success == true);
        vm.stopPrank();

        assertEq(user.balance, 0);

        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        ) = stakingContract.getOperator(OPERATOR_INDEX);
        assertEq(operatorAddress, operator);
        assertEq(feeRecipientAddress, feeRecipient);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 10);
        assertEq(available, 0);
        assert(deactivated == false);
    }

    function testImplicitDepositNotEnough(address user) public {
        assumeAddress(user);
        vm.deal(user, 32 * 11 ether);

        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("NotEnoughValidators()"));
        (bool _success, ) = address(stakingContract).call{value: 32 * 11 ether}("");
        assert(_success == true);
        vm.stopPrank();
    }

    function testImplicitDepositNotEnoughAfterFilled(address user) public {
        assumeAddress(user);
        vm.deal(user, 32 * 11 ether);

        vm.startPrank(user);
        (bool _success, ) = address(stakingContract).call{value: 32 * 10 ether}("");
        assert(_success == true);
        vm.stopPrank();
        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("NotEnoughValidators()"));
        (_success, ) = address(stakingContract).call{value: 32 ether}("");
        assert(_success == true);
        vm.stopPrank();
    }

    function testImplicitDepositInvalidAmount(address user) public {
        assumeAddress(user);

        vm.deal(user, 31.9 ether);

        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("InvalidDepositValue()"));
        (bool _success, ) = address(stakingContract).call{value: 31.9 ether}("");
        assert(_success == true);
        vm.stopPrank();
    }

    function testEditOperatorFee() public {
        assert(stakingContract.getOperatorFee() == 2000);
        vm.startPrank(admin);
        stakingContract.setOperatorFee(3000);
        vm.stopPrank();
        assert(stakingContract.getOperatorFee() == 3000);
    }

    function testEditGlobalFee() public {
        assert(stakingContract.getGlobalFee() == 1000);
        vm.startPrank(admin);
        stakingContract.setGlobalFee(2000);
        vm.stopPrank();
        assert(stakingContract.getGlobalFee() == 2000);
    }

    function testFeeRecipients() public {
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        address _elfr = stakingContract.getELFeeRecipient(PUBKEY_1);
        address _clfr = stakingContract.getCLFeeRecipient(PUBKEY_1);
        assert(_elfr != _clfr);
        vm.stopPrank();
    }

    function testWithdrawELFees() public {
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(PUBKEY_1);
        assert(elfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0);
        vm.deal(address(elfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.withdrawELFee(PUBKEY_1);
        assert(elfrBob.code.length != 0);
        assert(bob.balance == 0.9 ether);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0.02 ether);
        assert(address(treasury).balance == 0.08 ether);
    }

    function testBatchWithdrawELFees() public {
        vm.deal(bob, 64 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_2) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(PUBKEY_1);
        address elfrBob2 = stakingContract.getELFeeRecipient(PUBKEY_2);
        bytes memory publicKeys = BytesLib.concat(PUBKEY_1, PUBKEY_2);
        vm.deal(address(elfrBob), 1 ether);
        vm.deal(address(elfrBob2), 1 ether);
        vm.prank(bob);
        stakingContract.batchWithdrawELFee(publicKeys);
        assert(bob.balance == 1.8 ether);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0.04 ether);
        assert(address(treasury).balance == 0.16 ether);
    }

    function testBatchWithdrawELFees_asAdmin() public {
        vm.deal(bob, 64 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_2) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(PUBKEY_1);
        address elfrBob2 = stakingContract.getELFeeRecipient(PUBKEY_2);
        bytes memory publicKeys = BytesLib.concat(PUBKEY_1, PUBKEY_2);
        vm.deal(address(elfrBob), 1 ether);
        vm.deal(address(elfrBob2), 1 ether);
        vm.prank(admin);
        stakingContract.batchWithdrawELFee(publicKeys);
        assert(bob.balance == 1.8 ether);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0.04 ether);
        assert(address(treasury).balance == 0.16 ether);
    }

    function testBatchWithdrawELFees_WrongWithdrawerSecondKey() public {
        vm.deal(bob, 32 ether);
        address bob2 = makeAddr("bob2");
        vm.deal(bob2, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        vm.stopPrank();
        vm.prank(bob2);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_2) == bob2);
        address elfrBob = stakingContract.getELFeeRecipient(PUBKEY_1);
        address elfrBob2 = stakingContract.getELFeeRecipient(PUBKEY_2);
        bytes memory publicKeys = BytesLib.concat(PUBKEY_1, PUBKEY_2);
        vm.deal(address(elfrBob), 1 ether);
        vm.deal(address(elfrBob2), 1 ether);
        vm.expectRevert(abi.encodeWithSignature("InvalidWithdrawer()"));
        vm.prank(bob);
        stakingContract.batchWithdrawELFee(publicKeys);
    }

    function testBatchWithdrawELFees_WrongPublicKeys() public {
        vm.deal(bob, 64 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_2) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(PUBKEY_1);
        address elfrBob2 = stakingContract.getELFeeRecipient(PUBKEY_2);
        bytes memory publicKeys = BytesLib.concat(PUBKEY_1, PUBKEY_2);
        publicKeys = BytesLib.concat(publicKeys, hex"66");
        vm.deal(address(elfrBob), 1 ether);
        vm.deal(address(elfrBob2), 1 ether);
        vm.expectRevert(abi.encodeWithSignature("InvalidPublicKeys()"));
        vm.prank(bob);
        stakingContract.batchWithdrawELFee(publicKeys);
    }

    function testWithdrawELFeesEditedOperatorFee() public {
        vm.startPrank(admin);
        stakingContract.setOperatorFee(5000);
        vm.stopPrank();
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(PUBKEY_1);
        assert(elfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0);
        assert(address(treasury).balance == 0);
        vm.deal(address(elfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.withdrawELFee(PUBKEY_1);
        assert(elfrBob.code.length != 0);
        assert(bob.balance == 0.9 ether);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0.05 ether);
        assert(address(treasury).balance == 0.05 ether);
    }

    function testWithdrawELFeesAlreadyDeployed() public {
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(PUBKEY_1);
        assert(elfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0);
        vm.deal(address(elfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.withdrawELFee(PUBKEY_1);
        assert(elfrBob.code.length != 0);
        assert(bob.balance == 0.9 ether);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0.02 ether);
        assert(address(treasury).balance == 0.08 ether);
        vm.deal(address(elfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.withdrawELFee(PUBKEY_1);
        assert(bob.balance == 1.8 ether);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0.04 ether);
        assert(address(treasury).balance == 0.16 ether);
    }

    function testWithdrawELFeesEmptyWithdrawal() public {
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        vm.stopPrank();
        vm.expectRevert(abi.encodeWithSignature("ZeroBalanceWithdrawal()"));
        vm.prank(bob);
        stakingContract.withdrawELFee(PUBKEY_1);
    }

    function testWithdrawCLFeesExitedValidator() public {
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(PUBKEY_1);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(address(treasury).balance == 0 ether);
        assert(feeRecipient.balance == 0);
        vm.deal(address(clfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.requestValidatorsExit(PUBKEY_1);
        vm.deal(address(clfrBob), 33 ether);
        vm.prank(bob);
        stakingContract.withdrawCLFee(PUBKEY_1);
        assert(clfrBob.code.length != 0);
        assertApproxEqAbs(bob.balance, 32.90 ether, 10**5);
        assert(operator.balance == 0);
        assertApproxEqAbs(address(treasury).balance, 0.08 ether, 10**5);
        assertApproxEqAbs(feeRecipient.balance, 0.02 ether, 10**5);
    }

    function testWithdrawCLFeesExitedValidator_RewardsAfterRequest() public {
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(PUBKEY_1);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(address(treasury).balance == 0 ether);
        assert(feeRecipient.balance == 0);
        vm.deal(address(clfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.requestValidatorsExit(PUBKEY_1);
        vm.deal(address(clfrBob), 34 ether); // skimming + exit + rewards earned since last skimming
        vm.prank(bob);
        stakingContract.withdrawCLFee(PUBKEY_1);
        assert(clfrBob.code.length != 0);
        assertApproxEqAbs(bob.balance, 33.80 ether, 10**5);
        assert(operator.balance == 0);
        assertApproxEqAbs(address(treasury).balance, 0.16 ether, 10**5);
        assertApproxEqAbs(feeRecipient.balance, 0.04 ether, 10**5);
    }

    function testWithdrawCLFeesExitedValidator_UserTriesToStealFee() public {
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(PUBKEY_1);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(address(treasury).balance == 0 ether);
        assert(feeRecipient.balance == 0);
        vm.prank(bob);
        stakingContract.requestValidatorsExit(PUBKEY_1);
        vm.deal(address(clfrBob), 2 ether); // skimming happens between request & actual exit
        vm.deal(address(clfrBob), 32 ether); // withdrawer send 30 ETH to the fee recipient, using a self destructing contract
        vm.prank(bob);
        stakingContract.withdrawCLFee(PUBKEY_1);
        assertEq(bob.balance, 32 ether); // no fee was paid on the last withdraw, it was treated as an exiting validator
        vm.deal(address(clfrBob), 32 ether);
        vm.prank(bob);
        stakingContract.withdrawCLFee(PUBKEY_1); // The user tried to scam the commission, as a consequence the fee is applied to their principal
        assert(clfrBob.code.length != 0);
        assertEq(bob.balance, 60.8 ether);
        assert(operator.balance == 0);
        assertEq(address(treasury).balance, 2.56 ether);
        assertEq(feeRecipient.balance, 0.64 ether);
    }

    function testWithdrawCLFeesEditedOperatorFee() public {
        vm.startPrank(admin);
        stakingContract.setOperatorFee(5000);
        vm.stopPrank();
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(PUBKEY_1);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0);
        assert(address(treasury).balance == 0);
        vm.deal(address(clfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.requestValidatorsExit(PUBKEY_1);
        vm.deal(address(clfrBob), 33 ether);
        vm.prank(bob);
        stakingContract.withdrawCLFee(PUBKEY_1);
        assert(clfrBob.code.length != 0);

        assertApproxEqAbs(bob.balance, 32.90 ether, 10**5);
        assert(operator.balance == 0);
        assertApproxEqAbs(address(treasury).balance, 0.05 ether, 10**5);
        assertApproxEqAbs(feeRecipient.balance, 0.05 ether, 10**5);
    }

    function testWithdrawCLFeesSkimmedValidator() public {
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(PUBKEY_1);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0);
        assert(address(treasury).balance == 0);
        vm.deal(address(clfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.withdrawCLFee(PUBKEY_1);
        assert(clfrBob.code.length != 0);
        assertApproxEqAbs(bob.balance, 0.90 ether, 10**5);
        assert(operator.balance == 0);
        assertApproxEqAbs(address(treasury).balance, 0.08 ether, 10**5);
        assertApproxEqAbs(feeRecipient.balance, 0.02 ether, 10**5);
    }

    function testWithdrawCLFeesSkimmedValidator_asAdmin() public {
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(PUBKEY_1);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0);
        assert(address(treasury).balance == 0);
        vm.deal(address(clfrBob), 1 ether);
        vm.prank(admin);
        stakingContract.withdrawCLFee(PUBKEY_1);
        assert(clfrBob.code.length != 0);
        assertApproxEqAbs(bob.balance, 0.90 ether, 10**5);
        assert(operator.balance == 0);
        assertApproxEqAbs(address(treasury).balance, 0.08 ether, 10**5);
        assertApproxEqAbs(feeRecipient.balance, 0.02 ether, 10**5);
    }

    function testWithdrawCLFeesSkimmedValidator_asRandom() public {
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(PUBKEY_1);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0);
        assert(address(treasury).balance == 0);
        vm.deal(address(clfrBob), 1 ether);
        vm.expectRevert(abi.encodeWithSignature("InvalidWithdrawer()"));
        vm.prank(address(0xdede));
        stakingContract.withdrawCLFee(PUBKEY_1);
    }

    function testBatchWithdrawCLFees_asAdmin() public {
        vm.deal(bob, 64 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_2) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(PUBKEY_1);
        address clfrBob2 = stakingContract.getCLFeeRecipient(PUBKEY_2);
        bytes memory publicKeys = BytesLib.concat(PUBKEY_1, PUBKEY_2);
        vm.deal(address(clfrBob), 1 ether);
        vm.deal(address(clfrBob2), 1 ether);
        vm.prank(admin);
        stakingContract.batchWithdrawCLFee(publicKeys);
        assertApproxEqAbs(bob.balance, 1.8 ether, 10**6);
        assert(operator.balance == 0);
        assertApproxEqAbs(address(treasury).balance, 0.16 ether, 10**5);
        assertApproxEqAbs(feeRecipient.balance, 0.04 ether, 10**5);
    }

    function testBatchWithdrawCLFees_WrongSecondWithdrawer() public {
        vm.deal(bob, 32 ether);
        address bob2 = makeAddr("bob2");
        vm.deal(bob2, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        vm.stopPrank();
        vm.prank(bob2);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_2) == bob2);
        address clfrBob = stakingContract.getCLFeeRecipient(PUBKEY_1);
        address clfrBob2 = stakingContract.getCLFeeRecipient(PUBKEY_2);
        bytes memory publicKeys = BytesLib.concat(PUBKEY_1, PUBKEY_2);
        vm.deal(address(clfrBob), 1 ether);
        vm.deal(address(clfrBob2), 1 ether);
        vm.expectRevert(abi.encodeWithSignature("InvalidWithdrawer()"));
        vm.prank(bob);
        stakingContract.batchWithdrawCLFee(publicKeys);
    }

    function testBatchWithdrawCLFees() public {
        vm.deal(bob, 64 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_2) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(PUBKEY_1);
        address clfrBob2 = stakingContract.getCLFeeRecipient(PUBKEY_2);
        bytes memory publicKeys = BytesLib.concat(PUBKEY_1, PUBKEY_2);
        vm.deal(address(clfrBob), 1 ether);
        vm.deal(address(clfrBob2), 1 ether);
        vm.prank(bob);
        stakingContract.batchWithdrawCLFee(publicKeys);
        assertApproxEqAbs(bob.balance, 1.8 ether, 10**6);
        assert(operator.balance == 0);
        assertApproxEqAbs(address(treasury).balance, 0.16 ether, 10**5);
        assertApproxEqAbs(feeRecipient.balance, 0.04 ether, 10**5);
    }

    function testBatchWithdrawCLFees_WrongPublicKeys() public {
        vm.deal(bob, 64 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_2) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(PUBKEY_1);
        address clfrBob2 = stakingContract.getCLFeeRecipient(PUBKEY_2);
        bytes memory publicKeys = BytesLib.concat(PUBKEY_1, PUBKEY_2);
        publicKeys = BytesLib.concat(publicKeys, hex"66");
        vm.deal(address(clfrBob), 1 ether);
        vm.deal(address(clfrBob2), 1 ether);
        vm.expectRevert(abi.encodeWithSignature("InvalidPublicKeys()"));
        vm.prank(bob);
        stakingContract.batchWithdrawCLFee(publicKeys);
    }

    function testWithdrawCLFeesSlashedValidator() public {
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(PUBKEY_1);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        // Validator accumulated ~1 ETH or rewards then get slashed for 1 ETH + exit drain
        // Less than 32 ETH land on the fee recipient
        vm.deal(address(clfrBob), 31.95 ether);
        vm.prank(bob);
        stakingContract.withdrawCLFee(PUBKEY_1);

        // In this case the user will the be manually rebated and covered by insurance
        assert(clfrBob.code.length != 0);
        assertApproxEqAbs(bob.balance, 28.755 ether, 10**6);
        assertEq(operator.balance, 0);
    }

    function testWithdrawCLFeesSlashedValidatorWithRewards() public {
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(PUBKEY_1);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        vm.deal(address(clfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.requestValidatorsExit(PUBKEY_1);
        vm.deal(address(clfrBob), 28.755 ether);
        vm.prank(bob);
        stakingContract.withdrawCLFee(PUBKEY_1);

        // In this case the user will the be manually rebated and covered by insurance
        assert(clfrBob.code.length != 0);
        assertApproxEqAbs(bob.balance, 25.8795 ether, 10**6);
        assertEq(operator.balance, 0);
    }

    function testWithdrawCLFeesAlreadyDeployed() public {
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(PUBKEY_1);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0);
        vm.deal(address(clfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.withdrawCLFee(PUBKEY_1);
        assert(clfrBob.code.length != 0);
        assertApproxEqAbs(bob.balance, 0.90 ether, 10**5);
        assert(operator.balance == 0);
        assertApproxEqAbs(address(treasury).balance, 0.08 ether, 10**5);
        assertApproxEqAbs(feeRecipient.balance, 0.02 ether, 10**5);

        vm.deal(address(clfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.requestValidatorsExit(PUBKEY_1);
        vm.deal(address(clfrBob), 33 ether);
        vm.prank(bob);
        stakingContract.withdrawCLFee(PUBKEY_1);

        assertApproxEqAbs(bob.balance, 33.80 ether, 10**6);
        assert(operator.balance == 0);
        assertApproxEqAbs(address(treasury).balance, 0.16 ether, 10**5);
        assertApproxEqAbs(feeRecipient.balance, 0.04 ether, 10**5);
    }

    function testWithdrawCLFeesEmptyWithdrawal() public {
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        vm.expectRevert(abi.encodeWithSignature("ZeroBalanceWithdrawal()"));
        stakingContract.withdrawCLFee(PUBKEY_1);
        vm.stopPrank();
        assertEq(bob.balance, 0);
        assertEq(address(treasury).balance, 0);
        assertEq(feeRecipient.balance, 0);
    }

    function testWithdrawAllFees() public {
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        vm.stopPrank();

        address clfrBob = stakingContract.getCLFeeRecipient(PUBKEY_1);
        assert(clfrBob.code.length == 0);

        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0);
        assert(address(treasury).balance == 0);

        vm.deal(address(clfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.requestValidatorsExit(PUBKEY_1);
        vm.deal(address(clfrBob), 33 ether);
        address elfrBob = stakingContract.getELFeeRecipient(PUBKEY_1);
        assert(elfrBob.code.length == 0);
        vm.deal(address(elfrBob), 1 ether);

        vm.prank(bob);
        stakingContract.withdraw(PUBKEY_1);

        assertApproxEqAbs(bob.balance, 33.80 ether, 10**5);
        assert(operator.balance == 0);
        assertApproxEqAbs(address(treasury).balance, 0.16 ether, 10**5);
        assertApproxEqAbs(feeRecipient.balance, 0.04 ether, 10**5);
    }

    function test_withdraw_withSanctions_RecipientSanctioned() public {
        oracle.setSanction(bob, true);
        vm.prank(admin);
        stakingContract.setSanctionsOracle(address(oracle));

        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        vm.expectRevert(abi.encodeWithSignature("AddressSanctioned(address)", bob));
        stakingContract.deposit{value: 32 ether}();
        vm.stopPrank();
    }

    function testWithdrawAllFees_asAdmin() public {
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        vm.stopPrank();

        address clfrBob = stakingContract.getCLFeeRecipient(PUBKEY_1);
        assert(clfrBob.code.length == 0);
        vm.deal(address(clfrBob), 1 ether);

        address elfrBob = stakingContract.getELFeeRecipient(PUBKEY_1);
        assert(elfrBob.code.length == 0);
        vm.deal(address(elfrBob), 1 ether);

        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0);
        assert(address(treasury).balance == 0);

        vm.prank(admin);
        stakingContract.withdraw(PUBKEY_1);

        assertApproxEqAbs(bob.balance, 1.80 ether, 10**5);
        assert(operator.balance == 0);
        assertApproxEqAbs(address(treasury).balance, 0.16 ether, 10**5);
        assertApproxEqAbs(feeRecipient.balance, 0.04 ether, 10**5);
    }

    function testWithdrawAllFees_asRandom() public {
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        vm.stopPrank();

        address clfrBob = stakingContract.getCLFeeRecipient(PUBKEY_1);
        assert(clfrBob.code.length == 0);
        vm.deal(address(clfrBob), 33 ether);

        address elfrBob = stakingContract.getELFeeRecipient(PUBKEY_1);
        assert(elfrBob.code.length == 0);
        vm.deal(address(elfrBob), 1 ether);

        assert(bob.balance == 0);
        assert(operator.balance == 0);
        assert(feeRecipient.balance == 0);
        assert(address(treasury).balance == 0);

        vm.expectRevert(abi.encodeWithSignature("InvalidWithdrawer()"));
        vm.prank(address(0xdede));
        stakingContract.withdraw(PUBKEY_1);
    }

    function testBatchWithdrawAllFees() public {
        vm.deal(bob, 64 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_2) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(PUBKEY_1);
        address elfrBob2 = stakingContract.getELFeeRecipient(PUBKEY_2);
        vm.deal(address(elfrBob), 1 ether);
        vm.deal(address(elfrBob2), 1 ether);
        address clfrBob = stakingContract.getCLFeeRecipient(PUBKEY_1);
        address clfrBob2 = stakingContract.getCLFeeRecipient(PUBKEY_2);
        bytes memory publicKeys = BytesLib.concat(PUBKEY_1, PUBKEY_2);
        vm.prank(bob);
        vm.deal(address(clfrBob), 1 ether);
        vm.deal(address(clfrBob2), 1 ether);
        stakingContract.batchWithdraw(publicKeys);
        assertApproxEqAbs(bob.balance, 3.6 ether, 10**6);
        assert(operator.balance == 0);
        assertApproxEqAbs(address(treasury).balance, 0.32 ether, 10**5);
        assertApproxEqAbs(feeRecipient.balance, 0.08 ether, 10**5);
    }

    function testBatchWithdrawAllFees_asAdmin() public {
        vm.deal(bob, 64 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_2) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(PUBKEY_1);
        address elfrBob2 = stakingContract.getELFeeRecipient(PUBKEY_2);
        vm.deal(address(elfrBob), 1 ether);
        vm.deal(address(elfrBob2), 1 ether);
        address clfrBob = stakingContract.getCLFeeRecipient(PUBKEY_1);
        address clfrBob2 = stakingContract.getCLFeeRecipient(PUBKEY_2);
        bytes memory publicKeys = BytesLib.concat(PUBKEY_1, PUBKEY_2);
        vm.prank(admin);
        vm.deal(address(clfrBob), 1 ether);
        vm.deal(address(clfrBob2), 1 ether);
        stakingContract.batchWithdraw(publicKeys);
        assertApproxEqAbs(bob.balance, 3.6 ether, 10**6);
        assert(operator.balance == 0);
        assertApproxEqAbs(address(treasury).balance, 0.32 ether, 10**5);
        assertApproxEqAbs(feeRecipient.balance, 0.08 ether, 10**5);
    }

    function testBatchWithdrawAllFees_WrongWithdrawer() public {
        vm.deal(bob, 32 ether);
        address bob2 = makeAddr("bob2");
        vm.deal(bob2, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        vm.stopPrank();
        vm.prank(bob2);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_2) == bob2);
        address elfrBob = stakingContract.getELFeeRecipient(PUBKEY_1);
        address elfrBob2 = stakingContract.getELFeeRecipient(PUBKEY_2);
        vm.deal(address(elfrBob), 1 ether);
        vm.deal(address(elfrBob2), 1 ether);
        address clfrBob = stakingContract.getCLFeeRecipient(PUBKEY_1);
        address clfrBob2 = stakingContract.getCLFeeRecipient(PUBKEY_2);
        bytes memory publicKeys = BytesLib.concat(PUBKEY_1, PUBKEY_2);
        vm.prank(bob);
        vm.deal(address(clfrBob), 1 ether);
        vm.deal(address(clfrBob2), 1 ether);
        vm.expectRevert(abi.encodeWithSignature("InvalidWithdrawer()"));
        stakingContract.batchWithdraw(publicKeys);
    }

    function testBatchWithdrawAllFees_WrongPublicKeys() public {
        vm.deal(bob, 64 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_2) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(PUBKEY_1);
        address elfrBob2 = stakingContract.getELFeeRecipient(PUBKEY_2);
        vm.deal(address(elfrBob), 1 ether);
        vm.deal(address(elfrBob2), 1 ether);
        address clfrBob = stakingContract.getCLFeeRecipient(PUBKEY_1);
        address clfrBob2 = stakingContract.getCLFeeRecipient(PUBKEY_2);
        bytes memory publicKeys = BytesLib.concat(PUBKEY_1, PUBKEY_2);
        publicKeys = BytesLib.concat(publicKeys, hex"66");
        vm.prank(bob);
        vm.deal(address(clfrBob), 1 ether);
        vm.deal(address(clfrBob2), 1 ether);
        vm.expectRevert(abi.encodeWithSignature("InvalidPublicKeys()"));
        stakingContract.batchWithdraw(publicKeys);
    }

    function testBatchWithdrawELFees_10() public {
        assertEq(PUBLIC_KEYS.length, 480);
        vm.deal(bob, 320 ether);
        vm.startPrank(bob);
        for (uint256 i = 0; i < PUBLIC_KEYS.length; i += 48) {
            stakingContract.deposit{value: 32 ether}();
            assert(stakingContract.getWithdrawer(BytesLib.slice(PUBLIC_KEYS, i, 48)) == bob);
        }
        vm.stopPrank();
        for (uint256 i = 0; i < PUBLIC_KEYS.length; i += 48) {
            address elfrBob = stakingContract.getELFeeRecipient(BytesLib.slice(PUBLIC_KEYS, i, 48));
            vm.deal(address(elfrBob), 1 ether);
        }
        vm.prank(bob);
        stakingContract.batchWithdrawELFee(PUBLIC_KEYS);
        assertEq(bob.balance, 9 ether);
        assertEq(operator.balance, 0);
        assertEq(feeRecipient.balance, 0.2 ether);
        assertEq(address(treasury).balance, 0.8 ether);
    }

    function testBatchWithdrawCLFees_10() public {
        assertEq(PUBLIC_KEYS.length, 480);
        vm.deal(bob, 320 ether);
        vm.startPrank(bob);
        for (uint256 i = 0; i < PUBLIC_KEYS.length; i += 48) {
            stakingContract.deposit{value: 32 ether}();
            assert(stakingContract.getWithdrawer(BytesLib.slice(PUBLIC_KEYS, i, 48)) == bob);
        }
        vm.stopPrank();
        for (uint256 i = 0; i < PUBLIC_KEYS.length; i += 48) {
            address clfrBob = stakingContract.getCLFeeRecipient(BytesLib.slice(PUBLIC_KEYS, i, 48));
            vm.deal(address(clfrBob), 1 ether);
        }
        vm.prank(bob);
        stakingContract.batchWithdrawCLFee(PUBLIC_KEYS);
        assertApproxEqAbs(bob.balance, 9 ether, 10**7);
        assertEq(operator.balance, 0);
        assertApproxEqAbs(address(treasury).balance, 0.8 ether, 10**6);
        assertApproxEqAbs(feeRecipient.balance, 0.2 ether, 10**6);
    }

    function testBatchWithdrawAllFees_10() public {
        assertEq(PUBLIC_KEYS.length, 480);
        vm.deal(bob, 320 ether);
        vm.startPrank(bob);
        for (uint256 i = 0; i < PUBLIC_KEYS.length; i += 48) {
            stakingContract.deposit{value: 32 ether}();
            assert(stakingContract.getWithdrawer(BytesLib.slice(PUBLIC_KEYS, i, 48)) == bob);
        }
        vm.stopPrank();
        for (uint256 i = 0; i < PUBLIC_KEYS.length; i += 48) {
            address elfrBob = stakingContract.getELFeeRecipient(BytesLib.slice(PUBLIC_KEYS, i, 48));
            vm.deal(address(elfrBob), 1 ether);
            address clfrBob = stakingContract.getCLFeeRecipient(BytesLib.slice(PUBLIC_KEYS, i, 48));
            vm.deal(address(clfrBob), 1 ether);
        }
        vm.prank(bob);
        stakingContract.batchWithdraw(PUBLIC_KEYS);
        assertApproxEqAbs(bob.balance, 18 ether, 10**7);
        assertEq(operator.balance, 0);
        assertApproxEqAbs(address(treasury).balance, 1.6 ether, 10**6);
        assertApproxEqAbs(feeRecipient.balance, 0.4 ether, 10**6);
    }

    function testRequestValidatorsExits_OneValidator() public {
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        vm.stopPrank();
        vm.expectEmit(true, true, true, true);
        emit ExitRequest(bob, PUBKEY_1);
        vm.prank(bob);
        stakingContract.requestValidatorsExit(PUBKEY_1);
    }

    function test_requestValidatorExits_OracleActive_OwnerSanctioned() public {
        vm.prank(admin);
        stakingContract.setSanctionsOracle(address(oracle));
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        vm.stopPrank();

        oracle.setSanction(bob, true);
        vm.expectRevert(abi.encodeWithSignature("AddressSanctioned(address)", bob));

        vm.prank(bob);
        stakingContract.requestValidatorsExit(PUBKEY_1);
    }

    function testRequestValidatorsExits_TwoValidators() public {
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        vm.stopPrank();

        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_2) == bob);
        vm.stopPrank();

        bytes memory publicKeys = BytesLib.concat(PUBKEY_1, PUBKEY_2);

        vm.expectEmit(true, true, true, true);
        emit ExitRequest(bob, PUBKEY_1);
        vm.expectEmit(true, true, true, true);
        emit ExitRequest(bob, PUBKEY_2);
        vm.prank(bob);
        stakingContract.requestValidatorsExit(publicKeys);
    }

    function testRequestValidatorsExits_WrongWithdrawer() public {
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        vm.stopPrank();
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        vm.prank(address(1337));
        stakingContract.requestValidatorsExit(PUBKEY_1);
    }

    function testRequestValidatorsExits_WrongPublicKeys() public {
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        vm.stopPrank();
        vm.expectRevert(abi.encodeWithSignature("InvalidPublicKeys()"));
        vm.prank(bob);
        bytes
            memory corruptedPublicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd43607";
        stakingContract.requestValidatorsExit(corruptedPublicKey);
    }

    function testRequestValidatorsExits_WrongSecondWithdrawer() public {
        vm.deal(bob, 32 ether);
        vm.deal(alice, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_1) == bob);
        vm.stopPrank();
        vm.startPrank(alice);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(PUBKEY_2) == alice);
        vm.stopPrank();

        bytes memory publicKeys = BytesLib.concat(PUBKEY_1, PUBKEY_2);

        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        vm.prank(bob);
        stakingContract.requestValidatorsExit(publicKeys);
    }

    function test_block__NoDeposit_UserNotSanctioned() public {
        vm.prank(admin);
        stakingContract.blockAccount(bob, "");

        vm.deal(bob, 32 ether);

        (bool isBlocked, ) = stakingContract.isBlockedOrSanctioned(bob);

        assertTrue(isBlocked);

        vm.expectRevert(abi.encodeWithSignature("AddressBlocked(address)", bob));
        vm.prank(bob);
        stakingContract.deposit{value: 32 ether}();
    }

    function test_unblock__NoDeposit_UserNotSanctioned() public {
        vm.prank(admin);
        stakingContract.blockAccount(bob, "");

        (bool isBlocked, ) = stakingContract.isBlockedOrSanctioned(bob);

        assertTrue(isBlocked);

        vm.prank(admin);
        stakingContract.unblock(bob);

        vm.deal(bob, 32 ether);
        vm.prank(bob);
        stakingContract.deposit{value: 32 ether}();
    }

    function getPubkeyRoot(bytes memory pubkey) public pure returns (bytes32) {
        return sha256(abi.encodePacked(pubkey, bytes16(0)));
    }

    function test_block_UserDepositOneValidator_NotSanctioned() public {
        vm.deal(bob, 32 ether);

        vm.prank(bob);
        stakingContract.deposit{value: 32 ether}();

        vm.expectEmit(true, true, true, true);
        emit ExitRequest(bob, PUBKEY_1);
        vm.prank(admin);
        stakingContract.blockAccount(bob, PUBKEY_1);

        (bool isBlocked, ) = stakingContract.isBlockedOrSanctioned(bob);

        assertTrue(isBlocked);

        assertTrue(stakingContract.getExitRequestedFromRoot(getPubkeyRoot(PUBKEY_1)));
    }

    function test_block_UserDepositOneValidator_Sanctioned() public {
        vm.prank(admin);
        stakingContract.setSanctionsOracle(address(oracle));

        vm.deal(bob, 32 ether);

        vm.prank(bob);
        stakingContract.deposit{value: 32 ether}();

        oracle.setSanction(bob, true);

        vm.prank(admin);
        stakingContract.blockAccount(bob, PUBKEY_1);

        (bool isBlocked, ) = stakingContract.isBlockedOrSanctioned(bob);

        assertTrue(isBlocked);

        assertFalse(stakingContract.getExitRequestedFromRoot(getPubkeyRoot(PUBKEY_1)));
    }

    function test_block_UserDepositOneValidator_NotSanctioned_WrongPublicKey() public {
        vm.prank(admin);
        stakingContract.setSanctionsOracle(address(oracle));

        vm.deal(bob, 32 ether);

        vm.prank(bob);
        stakingContract.deposit{value: 32 ether}();

        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));

        vm.prank(admin);
        stakingContract.blockAccount(bob, PUBKEY_2);
    }

    error AddressSanctioned(address addr);

    function test_withdraw_from_recipient_owner_sanctioned() public {
        vm.prank(admin);
        stakingContract.setSanctionsOracle(address(oracle));
        assertFalse(oracle.isSanctioned(bob));

        vm.deal(bob, 32 ether);

        vm.prank(bob);
        stakingContract.deposit{value: 32 ether}();

        address clfr = stakingContract.getCLFeeRecipient(PUBKEY_1);
        vm.deal(clfr, 1 ether);

        vm.prank(bob);
        // First withdrawal deploy the recipient such that afterwards it's possible to trigger
        // the withdrawal from the recipient directly
        stakingContract.withdrawCLFee(PUBKEY_1);

        oracle.setSanction(bob, true);

        vm.deal(clfr, 1 ether);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSignature("AddressSanctioned(address)", bob));
        IFeeRecipient(clfr).withdraw();
    }
}
