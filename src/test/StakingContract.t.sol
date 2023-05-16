//SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.10;

import "forge-std/Vm.sol";
import "forge-std/Test.sol";
import "./UserFactory.sol";
import "../contracts/StakingContract.sol";
import "solmate/test/utils/DSTestPlus.sol";
import "../contracts/interfaces/IDepositContract.sol";
import "./UserFactory.sol";
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

contract StakingContractTest is DSTestPlus {
    Vm internal vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    address internal treasury;
    StakingContract internal stakingContract;
    DepositContractMock internal depositContract;
    UserFactory internal uf;

    address internal admin = address(1);
    address internal bob = address(2);
    address internal alice = address(3);
    address internal operatorOne = address(4);
    address internal feeRecipientOne = address(44);

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
            vm.startPrank(operatorOne);
            bytes memory pubkey = genBytes(25 * 48);
            bytes memory sigs = genBytes(25 * 96);
            startMeasure("");
            stakingContract.addValidators(0, 25, pubkey, sigs);
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
        uf = new UserFactory();
        address[] memory recipients = new address[](1);
        uint256[] memory percents = new uint256[](1);
        percents[0] = 10_000;
        treasury = address(99);
        stakingContract = new StakingContract();
        depositContract = new DepositContractMock();
        stakingContract.initialize_1(
            admin,
            treasury,
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
        stakingContract.addOperator(operatorOne, feeRecipientOne);
        vm.stopPrank();

        {
            bytes
                memory publicKeys = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e06014451b3fb9288549aff6dea9843b43e0c47a3b856f307732175230e254c0004e48b02414987088ac7003e148930017b49a1a8d4600f33d463c4afc07bbfc82703c9fcf81a5891f90a71c86a02faff443c6c3b2592bd44d5d3d7a93cb4aaaa105612496d61e68140a5418b468f872bf2f3e79f9cb0d9c3e889663fca02939b31e8ee3092203ee1417128e965c6406a07f68abf2ebe2689cf6c853ef126ffa8574c2a7d913e28de9147fa6b96706ea5bf9eacd1aba06edeaee155009fb912c00070774cc64136fcffde12ed731260bc5529df64da298f493561198e9d6acf42cf21e853ae7b2df85f27d2183149969d623b9237254c2cfe1d0082742eb042ac096d686dbe03c79ee31cbd03bb4682f8797043eed9f6e622814831ac5dfe1176552fb7f9b6ff38a149ae1d8414097a32fd96da6453c52fda13e3402a09e2fa6886daa4300f09c73e4bc2901b99c44744c5cfdca2994adc49ddccb195bda2510e50a4ae10de26cf96dee5e577689f51650a610a33da0a826ae47247d8d1189cb3386";

            bytes
                memory signatures = hex"ccb81f4485957f440bc17dbe760f374cbb112c6f12fa10e8709fac4522b30440d918c7bb867fa04f6b3cfbd977455f8f2fde586fdf3d7baa429e98e497ff871f3b8db1528b2b964fa24d26e377c74746496cc719c50dbf391fb3f74f5ca4b93a02a9f0007cd7b7d2af2d1b07c8600ab86a5d27dc51a29c2e3007c7a69cb73bcaecc764641e02370955dba100428d259d6475ee3566872bd43b0e73e55b9669e50f2b1666e57b326a5dfad655c7921e0dfb421b1ec59c8fdb48eb77421fd06966f393d619cbf13ff427df11dcb17026df25f35268de5b168e359c16f2a3d5fbc6376db44638d773c851c875f21222448433d285920e8bdc4f5cbff130d7387c0a9589324286aea398e5aacad3bbfe3992dfce62571f0e282ed9c29e3fa5b07aa5c81749589b1170d3b85a84331e2f6b8e26eadebfd569b225759f40bbd12d6c3d253ed3f379b014b2ea44cce54d362072e2d020ff139a903b7d87fc3fddc2e6657c83e0b79851c22c6e0e477463463c97d6cc0e2e2de5e35b227bddb285521be3766358abaf3159d89f68c9770e28278f177088cfc4089b817effaaecabdffa4e66427868b105cb9348ea2d84eeea059a5d1ff3277d6f9cf656fc973d07cabed70fb8f8eb2798a65d207a8e1f8a26910949db9fa62d62bc15ecc097a93a27a1873405b8589a4ddf0ecf0303c6031484562b32eb7881975026524d6d4a9de6cd73fe2c324501586b9b6fa6bce950bbd21472278302f83dbfd6be036f2fc36d299d66578e844be3d6aa8314fab468f038fd6e130ada0a886fccfb2fd843f7dd07e8968401bbe2af7345fce52ba4b310b30af2d54b15669d06c206682c1730ab6b17787e361f04401f78dc5cbd5fac955df4e83c24cdabfabdb3f4ea40961d04a5ca166c17694fca144025b47131a68ddb230d36fe6e831e82624c9a925d706bff86982852b26ebf019a3f6ee36aedbbc6bec2d50531a233e09225493d3c5fd48379aec373baf622fb9feed6261e5296e5ae6601e7523c7f386801ed63a344b07106a0d03e5848209db5e114c0e67884916a43a1bfb77d9b8ea113c3ba8cad4b006aafeadcc31e70e85c5efecaf807154d011c1413340d4b592d2f270fb48b2050e08493c1427ddfac8dcc27fe434d32a35dcbddbcb1c4e22ead6734a4ac910f6768bc9ff6b355c1151695e41121cdcc9d9d3b18cf4d66ca3c1db0527c471a0dcf256590602a7269dcb26175e7eb370bd9794ac8ab558bea69e6a92d8e818b675a80e2df0516b8307291d93cb85d959ac60d47b46455a7ab0a38687c747c6d2d9e8c20ccf74dc6cdf145ec06805d4ac24a39aec2f5cd6e26e63e3d043a31c42411e4";

            vm.startPrank(operatorOne);
            stakingContract.addValidators(0, 10, publicKeys, signatures);
            vm.stopPrank();
        }

        {
            vm.startPrank(admin);
            stakingContract.setOperatorLimit(0, 10, block.number);
            vm.stopPrank();
        }
    }

    function testGetAdmin() public {
        assertEq(stakingContract.getAdmin(), admin);
    }

    event ChangedAdmin(address newAdmin);

    function testSetAdmin(uint256 _adminSalt) public {
        address newAdmin = uf._new(_adminSalt);
        assertEq(stakingContract.getAdmin(), admin);

        // Start ownership transfer process.
        vm.startPrank(admin);
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

    function testTransferOwnershipUnauthorized(uint256 _adminSalt) public {
        address newAdmin = uf._new(_adminSalt);
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        stakingContract.transferOwnership(newAdmin);
    }

    function testAcceptOwnershipUnauthorized(uint256 _adminSalt) public {
        address newAdmin = uf._new(_adminSalt);

        vm.startPrank(admin);
        stakingContract.transferOwnership(newAdmin);
        vm.stopPrank();

        address randomUser = uf._new(_adminSalt);
        // A random user tries to accept new admin's role.
        vm.startPrank(randomUser);
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        stakingContract.acceptOwnership();
        vm.stopPrank();
    }

    function testGetOperator() public {
        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 0);
        assertEq(available, 10);
        assert(deactivated == false);
    }

    function testAddOperatorUnauthorized(uint256 _operatorSalt) public {
        address newOperator = uf._new(_operatorSalt);
        address newOperatorFeeRecipient = uf._new(_operatorSalt);

        uint256 operatorIndex;

        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        operatorIndex = stakingContract.addOperator(newOperator, newOperatorFeeRecipient);
    }

    function testSetOperatorAddresses(uint256 _operatorSalt) public {
        address newOperatorFeeRecipient = uf._new(_operatorSalt);

        uint256 operatorIndex = 0;

        address updatedOperator = uf._new(_operatorSalt);

        // Try to update the operator address
        vm.startPrank(feeRecipientOne);
        stakingContract.setOperatorAddresses(operatorIndex, updatedOperator, newOperatorFeeRecipient);
        vm.stopPrank();

        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        ) = stakingContract.getOperator(operatorIndex);
        assertEq(operatorAddress, updatedOperator);
        assertEq(feeRecipientAddress, newOperatorFeeRecipient);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 0);
        assertEq(available, 10);
        assert(deactivated == false);
    }

    function testSetOperatorAddressesUnauthorized(uint256 _operatorSalt) public {
        address newOperator = uf._new(_operatorSalt);
        address wrongOperatorFeeRecipient = uf._new(_operatorSalt);

        uint256 operatorIndex = 0;

        // Try to update the operator addresses
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        stakingContract.setOperatorAddresses(operatorIndex, newOperator, wrongOperatorFeeRecipient);
    }

    event ChangedOperatorLimit(uint256 operatorIndex, uint256 limit);

    function testSetOperatorLimit(uint256 _operatorSalt, uint8 _limit) public {
        uint256 operatorIndex = 0;

        (, , uint256 limit, , , , ) = stakingContract.getOperator(operatorIndex);
        assertEq(limit, 10);

        if (_limit > 0) {
            vm.startPrank(operatorOne);
            stakingContract.addValidators(
                operatorIndex,
                _limit,
                genBytes(48 * uint256(_limit)),
                genBytes(96 * uint256(_limit))
            );
            vm.stopPrank();
        }

        vm.startPrank(admin);
        vm.expectEmit(true, true, true, true);
        emit ChangedOperatorLimit(operatorIndex, _limit);
        stakingContract.setOperatorLimit(operatorIndex, _limit, block.number);
        vm.stopPrank();

        (, , limit, , , , ) = stakingContract.getOperator(operatorIndex);
        assertEq(limit, _limit);
    }

    function testSetOperatorLimit_snapshotRevert(uint256 _operatorSalt, uint8 _limit) public {
        vm.assume(_limit > 10); // Ensuring we raise the existing limit

        (, , uint256 limit, , , , ) = stakingContract.getOperator(0);
        assertEq(limit, 10);

        vm.roll(1000);
        if (_limit > 0) {
            vm.startPrank(operatorOne);
            stakingContract.addValidators(0, _limit, genBytes(48 * uint256(_limit)), genBytes(96 * uint256(_limit)));
            vm.stopPrank();
        }

        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSignature("LastEditAfterSnapshot()"));
        stakingContract.setOperatorLimit(0, _limit, block.number - 10);
        vm.stopPrank();
    }

    function testSetOperatorLimitUnauthorized() public {
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        stakingContract.setOperatorLimit(0, 10, block.number);
    }

    function testSetOperatorLimitTooHighUnauthorized() public {
        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSignature("OperatorLimitTooHigh(uint256,uint256)", 11, 10));
        stakingContract.setOperatorLimit(0, 11, block.number);
        vm.stopPrank();
    }

    function testSetOperatorLimitDeactivated(uint256 _operatorSalt, uint8 _limit) public {
        uint256 operatorIndex = 0;

        (, , uint256 limit, , , , ) = stakingContract.getOperator(operatorIndex);
        assertEq(limit, 10);

        if (_limit > 0) {
            vm.startPrank(operatorOne);
            stakingContract.addValidators(
                operatorIndex,
                _limit,
                genBytes(48 * uint256(_limit)),
                genBytes(96 * uint256(_limit))
            );
            vm.stopPrank();
        }

        vm.startPrank(admin);
        stakingContract.deactivateOperator(operatorIndex, operatorOne);
        vm.expectRevert(abi.encodeWithSignature("Deactivated()"));
        stakingContract.setOperatorLimit(operatorIndex, _limit, block.number);
        vm.stopPrank();
    }

    function testAddValidatorsOperatorOne() public {
        bytes
            memory publicKeys = hex"0c74b6d3d877bbb2083f1bcc83b302f3ed533eaf3cd39cff97daf2c7b9b776168481aa7b51778df673a37049886f25b07f03dbc79d85fa9d41f9eefa8e598353b652aadf497673744527c73127f872b91cf31ec8041dae1b3a4238683cf442ea23a95fe68b400ab42b14e8c99280a057d1d840e80723c3622b38e6acd1f471bf247cf62312c9b863a75ac0d270cefa4f84fd8586dbda15c67c1a46e85cf56c60550f54cb082770baf3d2bbf4c33f5254bd0b93e017f3ed036b13baec41bb69085f9eff48651be38c8f9e1f67b643f84ec356864aaa057f0042b121b9d040ed9be3f5cc9cc659d8f8fc02575ed3c25708adac2c8d0c50ab7e4599ce9edf300d98e1cfcfc8e0022a24c712f0769de99a3389bac1cdca92ae20fba323142fe2e8d09ef2cb59c3f822779b3fe6410cddce7255d35db01093cc435c0a35bbb4cd8d4eb3bd2cc597c49a7a909c16f67fe8b6702d5d0c22ad189b1c45325190015b0017606f768c7aa2006cc19dfeb5f367eae9dd17a5c307705db1f5cec552fc038e5fa3a76352d9621a4d74b1fd7e1707c7bfb5e912e2b5a33a2f34a419055d0c4065aa787f743aff953d73441e96ffc9b0f5a3248c23398518a758aec8451b626bff7eed063a3b11bf661d10ad6dac5ee62f47be125e3c668e14b3c704d736b4fb1e";
        bytes
            memory signatures = hex"fe41ffbe702fb08d01063c9cd99fac11a16e921c784e681e365db00c4bd6760df67cfc0d0555a8ee8bf534a2c0987b7949b18dba726ced579240fa063274bc7ab25e44b758c452c433debfebbc075cbe105f07502402a9591dc891640a9f2b34fe0863bf987ff4b5a601b0ffcecc185f04847e0b97d3fb9457c32efb9c3ce35520308cfcc8ca78d5d4da164f6d1575d32fe466b8076bc4056ad97fa3e3607a60e5e420bdec413e5ffcc3119b1b89a957b14a437e009a858c4c40c0f1fc7f3d1ad83bc96ada6c2c772260637774e5fbdc60791db6de3a31e136c28106b35c21932a8ed610306f0723675730e31d3deceff4f912e6070c9efcd6e3f0c9ad4a0e203f437f21679b87d46351714b5a1b6226f8ffadd19e18f85c918461ab67291e1c8cdfdc05280adf2b923f1269cf7de8bd351a7ede13524e836cbfc7ba22db91aaa5c9a0729a469985f5bd844347ba9a9b4019f4ad42c2025457cf48557494ac3ce6e311a1ded3e903cd3009d18133015d445d02a3ce3858781b582d28701a311ddb271f8a0c91c65b32cc13c512c35e5be9bb9dc556dfd3249a3733f58426718974820f17b3242a089e29b129fcea37c8b84996e2c725b59efccee24068625584e583700346f823ce92e11ac9db5964ca6300905c5e9f294330037ec1cb7d9b8fc28829b98fcc0fc405afcd54f43cb4a14e8cab3f5aa979fe2c3492fe295e1a50170e8857bd94e5b009bcec9626e6eb137b272882037202da7329dadcb5b99bbd7835b8875d696dab41774dcb559bfb4c79a5337efc5f1606bc7c2752389a49b6a578f0c7c58e2bf9efc55eef19beaf3de94da90c712ca3891ac71a6ff6d778a1c0c31f77fdde2c4b7f29adf8ccf000050e9e4829d2de36fda8d6b26020e6f0ece339e9ad96c01b166301238e1aaa30ddfb978968361a5f9d3fcaa381973c967c0dd88c6d54d00fa375ab4df3be57c4360b69d7634e95e4d4201da8f2348d0ce53be690146f0049d5d173a635d21406b10ed23ec9996bd0a43b812df363986fb8dedf5be1cdb3f85a5090460511af617507d24657e3733310b42e1406070a0316620037da35c5227bb85d3aacf3aebf750265838994e03a8770cdc1c31723ca1037232c32d21f31eee561575b18b1b4c0f027f270898aed60ab4bfe41160cd989cd5bdfeb795097ff01cd0ff41fea96311e92798c0a619aa957772cfd408747fc30dcb39210839a4c70b87d3ad881207fa5eee926bc2c6936ce10b382c7a37606d40bb1cf2637768255aae4a4cd18ed7004e3046520bea92c66a7074e4b46d3d566703e44d0c3f9ef49a2ff30632fe3f6a409178db66423809514cd7473f83d0c";

        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 0);
        assertEq(available, 10);
        assert(deactivated == false);

        bytes
            memory pubKey1 = hex"0c74b6d3d877bbb2083f1bcc83b302f3ed533eaf3cd39cff97daf2c7b9b776168481aa7b51778df673a37049886f25b0";
        assertFalse(stakingContract.getEnabledFromPublicKeyRoot(sha256(abi.encodePacked(pubKey1, bytes16(0)))));

        vm.startPrank(operatorOne);
        vm.expectEmit(true, true, true, true);
        emit ValidatorKeysAdded(0, publicKeys, signatures);
        stakingContract.addValidators(0, 10, publicKeys, signatures);
        vm.stopPrank();

        assertTrue(stakingContract.getEnabledFromPublicKeyRoot(sha256(abi.encodePacked(pubKey1, bytes16(0)))));

        (operatorAddress, feeRecipientAddress, limit, keys, funded, available, deactivated) = stakingContract
            .getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 20);
        assertEq(funded, 0);
        assertEq(available, 10);
        assert(deactivated == false);

        vm.startPrank(admin);
        stakingContract.setOperatorLimit(0, 20, block.number);
        vm.stopPrank();

        (operatorAddress, feeRecipientAddress, limit, keys, funded, available, deactivated) = stakingContract
            .getOperator(0);

        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 20);
        assertEq(keys, 20);
        assertEq(funded, 0);
        assertEq(available, 20);
        assert(deactivated == false);
    }

    event DeactivatedOperator(uint256 _operatorIndex);
    event ActivatedOperator(uint256 _operatorIndex);

    function testAddValidatorsDeactivatedOperatorOne() public {
        bytes
            memory publicKeys = hex"0c74b6d3d877bbb2083f1bcc83b302f3ed533eaf3cd39cff97daf2c7b9b776168481aa7b51778df673a37049886f25b07f03dbc79d85fa9d41f9eefa8e598353b652aadf497673744527c73127f872b91cf31ec8041dae1b3a4238683cf442ea23a95fe68b400ab42b14e8c99280a057d1d840e80723c3622b38e6acd1f471bf247cf62312c9b863a75ac0d270cefa4f84fd8586dbda15c67c1a46e85cf56c60550f54cb082770baf3d2bbf4c33f5254bd0b93e017f3ed036b13baec41bb69085f9eff48651be38c8f9e1f67b643f84ec356864aaa057f0042b121b9d040ed9be3f5cc9cc659d8f8fc02575ed3c25708adac2c8d0c50ab7e4599ce9edf300d98e1cfcfc8e0022a24c712f0769de99a3389bac1cdca92ae20fba323142fe2e8d09ef2cb59c3f822779b3fe6410cddce7255d35db01093cc435c0a35bbb4cd8d4eb3bd2cc597c49a7a909c16f67fe8b6702d5d0c22ad189b1c45325190015b0017606f768c7aa2006cc19dfeb5f367eae9dd17a5c307705db1f5cec552fc038e5fa3a76352d9621a4d74b1fd7e1707c7bfb5e912e2b5a33a2f34a419055d0c4065aa787f743aff953d73441e96ffc9b0f5a3248c23398518a758aec8451b626bff7eed063a3b11bf661d10ad6dac5ee62f47be125e3c668e14b3c704d736b4fb1e";
        bytes
            memory signatures = hex"fe41ffbe702fb08d01063c9cd99fac11a16e921c784e681e365db00c4bd6760df67cfc0d0555a8ee8bf534a2c0987b7949b18dba726ced579240fa063274bc7ab25e44b758c452c433debfebbc075cbe105f07502402a9591dc891640a9f2b34fe0863bf987ff4b5a601b0ffcecc185f04847e0b97d3fb9457c32efb9c3ce35520308cfcc8ca78d5d4da164f6d1575d32fe466b8076bc4056ad97fa3e3607a60e5e420bdec413e5ffcc3119b1b89a957b14a437e009a858c4c40c0f1fc7f3d1ad83bc96ada6c2c772260637774e5fbdc60791db6de3a31e136c28106b35c21932a8ed610306f0723675730e31d3deceff4f912e6070c9efcd6e3f0c9ad4a0e203f437f21679b87d46351714b5a1b6226f8ffadd19e18f85c918461ab67291e1c8cdfdc05280adf2b923f1269cf7de8bd351a7ede13524e836cbfc7ba22db91aaa5c9a0729a469985f5bd844347ba9a9b4019f4ad42c2025457cf48557494ac3ce6e311a1ded3e903cd3009d18133015d445d02a3ce3858781b582d28701a311ddb271f8a0c91c65b32cc13c512c35e5be9bb9dc556dfd3249a3733f58426718974820f17b3242a089e29b129fcea37c8b84996e2c725b59efccee24068625584e583700346f823ce92e11ac9db5964ca6300905c5e9f294330037ec1cb7d9b8fc28829b98fcc0fc405afcd54f43cb4a14e8cab3f5aa979fe2c3492fe295e1a50170e8857bd94e5b009bcec9626e6eb137b272882037202da7329dadcb5b99bbd7835b8875d696dab41774dcb559bfb4c79a5337efc5f1606bc7c2752389a49b6a578f0c7c58e2bf9efc55eef19beaf3de94da90c712ca3891ac71a6ff6d778a1c0c31f77fdde2c4b7f29adf8ccf000050e9e4829d2de36fda8d6b26020e6f0ece339e9ad96c01b166301238e1aaa30ddfb978968361a5f9d3fcaa381973c967c0dd88c6d54d00fa375ab4df3be57c4360b69d7634e95e4d4201da8f2348d0ce53be690146f0049d5d173a635d21406b10ed23ec9996bd0a43b812df363986fb8dedf5be1cdb3f85a5090460511af617507d24657e3733310b42e1406070a0316620037da35c5227bb85d3aacf3aebf750265838994e03a8770cdc1c31723ca1037232c32d21f31eee561575b18b1b4c0f027f270898aed60ab4bfe41160cd989cd5bdfeb795097ff01cd0ff41fea96311e92798c0a619aa957772cfd408747fc30dcb39210839a4c70b87d3ad881207fa5eee926bc2c6936ce10b382c7a37606d40bb1cf2637768255aae4a4cd18ed7004e3046520bea92c66a7074e4b46d3d566703e44d0c3f9ef49a2ff30632fe3f6a409178db66423809514cd7473f83d0c";

        (
            address operatorAddress,
            address feeRecipient,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipient, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 0);
        assertEq(available, 10);
        assert(deactivated == false);

        vm.startPrank(admin);
        vm.expectEmit(true, true, true, true);
        emit DeactivatedOperator(0);
        stakingContract.deactivateOperator(0, address(1));
        vm.stopPrank();

        (operatorAddress, feeRecipient, limit, keys, funded, available, deactivated) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipient, address(1));
        assertEq(limit, 0);
        assertEq(keys, 10);
        assertEq(funded, 0);
        assertEq(available, 0);
        assert(deactivated == true);

        vm.startPrank(operatorOne);
        vm.expectRevert(abi.encodeWithSignature("Deactivated()"));
        stakingContract.addValidators(0, 10, publicKeys, signatures);
        vm.stopPrank();

        vm.startPrank(operatorOne);
        uint256[] memory indexes = new uint256[](1);
        indexes[0] = 0;
        vm.expectRevert(abi.encodeWithSignature("Deactivated()"));
        stakingContract.removeValidators(0, indexes);
        vm.stopPrank();

        vm.startPrank(feeRecipientOne);
        vm.expectRevert(abi.encodeWithSignature("Deactivated()"));
        stakingContract.setOperatorAddresses(0, operatorOne, feeRecipientOne);
        vm.stopPrank();

        vm.startPrank(admin);
        vm.expectEmit(true, true, true, true);
        emit ActivatedOperator(0);
        stakingContract.activateOperator(0, feeRecipientOne);
        vm.stopPrank();

        vm.startPrank(operatorOne);
        stakingContract.addValidators(0, 10, publicKeys, signatures);
        vm.stopPrank();

        (operatorAddress, feeRecipient, limit, keys, funded, available, deactivated) = stakingContract.getOperator(0);

        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipient, feeRecipientOne);
        assertEq(limit, 0);
        assertEq(keys, 20);
        assertEq(funded, 0);
        assertEq(available, 0);
        assert(deactivated == false);
    }

    function testAddValidatorsOperatorOneDuplicateKeys() public {
        bytes
            memory publicKeys = hex"0c74b6d3d877bbb2083f1bcc83b302f3ed533eaf3cd39cff97daf2c7b9b776168481aa7b51778df673a37049886f25b07f03dbc79d85fa9d41f9eefa8e598353b652aadf497673744527c73127f872b91cf31ec8041dae1b3a4238683cf442ea23a95fe68b400ab42b14e8c99280a057d1d840e80723c3622b38e6acd1f471bf247cf62312c9b863a75ac0d270cefa4f84fd8586dbda15c67c1a46e85cf56c60550f54cb082770baf3d2bbf4c33f5254bd0b93e017f3ed036b13baec41bb69085f9eff48651be38c8f9e1f67b643f84ec356864aaa057f0042b121b9d040ed9be3f5cc9cc659d8f8fc02575ed3c25708adac2c8d0c50ab7e4599ce9edf300d98e1cfcfc8e0022a24c712f0769de99a3389bac1cdca92ae20fba323142fe2e8d09ef2cb59c3f822779b3fe6410cddce7255d35db01093cc435c0a35bbb4cd8d4eb3bd2cc597c49a7a909c16f67fe8b6702d5d0c22ad189b1c45325190015b0017606f768c7aa2006cc19dfeb5f367eae9dd17a5c307705db1f5cec552fc038e5fa3a76352d9621a4d74b1fd7e1707c7bfb5e912e2b5a33a2f34a419055d0c4065aa787f743aff953d73441e96ffc9b0f5a3248c23398518a758aec8451b626bff7eed063a3b11bf661d10ad6dac5ee62f47be125e3c668e14b3c704d736b4fb1e";
        bytes
            memory signatures = hex"fe41ffbe702fb08d01063c9cd99fac11a16e921c784e681e365db00c4bd6760df67cfc0d0555a8ee8bf534a2c0987b7949b18dba726ced579240fa063274bc7ab25e44b758c452c433debfebbc075cbe105f07502402a9591dc891640a9f2b34fe0863bf987ff4b5a601b0ffcecc185f04847e0b97d3fb9457c32efb9c3ce35520308cfcc8ca78d5d4da164f6d1575d32fe466b8076bc4056ad97fa3e3607a60e5e420bdec413e5ffcc3119b1b89a957b14a437e009a858c4c40c0f1fc7f3d1ad83bc96ada6c2c772260637774e5fbdc60791db6de3a31e136c28106b35c21932a8ed610306f0723675730e31d3deceff4f912e6070c9efcd6e3f0c9ad4a0e203f437f21679b87d46351714b5a1b6226f8ffadd19e18f85c918461ab67291e1c8cdfdc05280adf2b923f1269cf7de8bd351a7ede13524e836cbfc7ba22db91aaa5c9a0729a469985f5bd844347ba9a9b4019f4ad42c2025457cf48557494ac3ce6e311a1ded3e903cd3009d18133015d445d02a3ce3858781b582d28701a311ddb271f8a0c91c65b32cc13c512c35e5be9bb9dc556dfd3249a3733f58426718974820f17b3242a089e29b129fcea37c8b84996e2c725b59efccee24068625584e583700346f823ce92e11ac9db5964ca6300905c5e9f294330037ec1cb7d9b8fc28829b98fcc0fc405afcd54f43cb4a14e8cab3f5aa979fe2c3492fe295e1a50170e8857bd94e5b009bcec9626e6eb137b272882037202da7329dadcb5b99bbd7835b8875d696dab41774dcb559bfb4c79a5337efc5f1606bc7c2752389a49b6a578f0c7c58e2bf9efc55eef19beaf3de94da90c712ca3891ac71a6ff6d778a1c0c31f77fdde2c4b7f29adf8ccf000050e9e4829d2de36fda8d6b26020e6f0ece339e9ad96c01b166301238e1aaa30ddfb978968361a5f9d3fcaa381973c967c0dd88c6d54d00fa375ab4df3be57c4360b69d7634e95e4d4201da8f2348d0ce53be690146f0049d5d173a635d21406b10ed23ec9996bd0a43b812df363986fb8dedf5be1cdb3f85a5090460511af617507d24657e3733310b42e1406070a0316620037da35c5227bb85d3aacf3aebf750265838994e03a8770cdc1c31723ca1037232c32d21f31eee561575b18b1b4c0f027f270898aed60ab4bfe41160cd989cd5bdfeb795097ff01cd0ff41fea96311e92798c0a619aa957772cfd408747fc30dcb39210839a4c70b87d3ad881207fa5eee926bc2c6936ce10b382c7a37606d40bb1cf2637768255aae4a4cd18ed7004e3046520bea92c66a7074e4b46d3d566703e44d0c3f9ef49a2ff30632fe3f6a409178db66423809514cd7473f83d0c";

        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 0);
        assertEq(available, 10);
        assert(deactivated == false);

        vm.startPrank(operatorOne);
        stakingContract.addValidators(0, 10, publicKeys, signatures);
        vm.stopPrank();

        vm.startPrank(operatorOne);
        vm.expectRevert(
            abi.encodeWithSignature(
                "DuplicateValidatorKey(bytes)",
                hex"0c74b6d3d877bbb2083f1bcc83b302f3ed533eaf3cd39cff97daf2c7b9b776168481aa7b51778df673a37049886f25b0"
            )
        );
        stakingContract.addValidators(0, 10, publicKeys, signatures);
        vm.stopPrank();
    }

    function testAddValidatorsInvalidPubKey() public {
        bytes
            memory publicKeys = hex"0c74b6d3d877bbb2083f1bcc83b302f3ed533eaf3cd39cff97daf2c7b9b776168481aa7b51778df673a37049886f25b07f03dbc79d85fa9d41f9eefa8e598353b652aadf497673744527c73127f872b91cf31ec8041dae1b3a4238683cf442ea23a95fe68b400ab42b14e8c99280a057d1d840e80723c3622b38e6acd1f471bf247cf62312c9b863a75ac0d270cefa4f84fd8586dbda15c67c1a46e85cf56c60550f54cb082770baf3d2bbf4c33f5254bd0b93e017f3ed036b13baec41bb69085f9eff48651be38c8f9e1f67b643f84ec356864aaa057f0042b121b9d040ed9be3f5cc9cc659d8f8fc02575ed3c25708adac2c8d0c50ab7e4599ce9edf300d98e1cfcfc8e0022a24c712f0769de99a3389bac1cdca92ae20fba323142fe2e8d09ef2cb59c3f822779b3fe6410cddce7255d35db01093cc435c0a35bbb4cd8d4eb3bd2cc597c49a7a909c16f67fe8b6702d5d0c22ad189b1c45325190015b0017606f768c7aa2006cc19dfeb5f367eae9dd17a5c307705db1f5cec552fc038e5fa3a76352d9621a4d74b1fd7e1707c7bfb5e912e2b5a33a2f34a419055d0c4065aa787f743aff953d73441e96ffc9b0f5a3248c23398518a758aec8451b626bff7eed063a3b11bf661d10ad6dac5ee62f47be125e3c668e14b3c704d736b4fb";
        bytes
            memory signatures = hex"fe41ffbe702fb08d01063c9cd99fac11a16e921c784e681e365db00c4bd6760df67cfc0d0555a8ee8bf534a2c0987b7949b18dba726ced579240fa063274bc7ab25e44b758c452c433debfebbc075cbe105f07502402a9591dc891640a9f2b34fe0863bf987ff4b5a601b0ffcecc185f04847e0b97d3fb9457c32efb9c3ce35520308cfcc8ca78d5d4da164f6d1575d32fe466b8076bc4056ad97fa3e3607a60e5e420bdec413e5ffcc3119b1b89a957b14a437e009a858c4c40c0f1fc7f3d1ad83bc96ada6c2c772260637774e5fbdc60791db6de3a31e136c28106b35c21932a8ed610306f0723675730e31d3deceff4f912e6070c9efcd6e3f0c9ad4a0e203f437f21679b87d46351714b5a1b6226f8ffadd19e18f85c918461ab67291e1c8cdfdc05280adf2b923f1269cf7de8bd351a7ede13524e836cbfc7ba22db91aaa5c9a0729a469985f5bd844347ba9a9b4019f4ad42c2025457cf48557494ac3ce6e311a1ded3e903cd3009d18133015d445d02a3ce3858781b582d28701a311ddb271f8a0c91c65b32cc13c512c35e5be9bb9dc556dfd3249a3733f58426718974820f17b3242a089e29b129fcea37c8b84996e2c725b59efccee24068625584e583700346f823ce92e11ac9db5964ca6300905c5e9f294330037ec1cb7d9b8fc28829b98fcc0fc405afcd54f43cb4a14e8cab3f5aa979fe2c3492fe295e1a50170e8857bd94e5b009bcec9626e6eb137b272882037202da7329dadcb5b99bbd7835b8875d696dab41774dcb559bfb4c79a5337efc5f1606bc7c2752389a49b6a578f0c7c58e2bf9efc55eef19beaf3de94da90c712ca3891ac71a6ff6d778a1c0c31f77fdde2c4b7f29adf8ccf000050e9e4829d2de36fda8d6b26020e6f0ece339e9ad96c01b166301238e1aaa30ddfb978968361a5f9d3fcaa381973c967c0dd88c6d54d00fa375ab4df3be57c4360b69d7634e95e4d4201da8f2348d0ce53be690146f0049d5d173a635d21406b10ed23ec9996bd0a43b812df363986fb8dedf5be1cdb3f85a5090460511af617507d24657e3733310b42e1406070a0316620037da35c5227bb85d3aacf3aebf750265838994e03a8770cdc1c31723ca1037232c32d21f31eee561575b18b1b4c0f027f270898aed60ab4bfe41160cd989cd5bdfeb795097ff01cd0ff41fea96311e92798c0a619aa957772cfd408747fc30dcb39210839a4c70b87d3ad881207fa5eee926bc2c6936ce10b382c7a37606d40bb1cf2637768255aae4a4cd18ed7004e3046520bea92c66a7074e4b46d3d566703e44d0c3f9ef49a2ff30632fe3f6a409178db66423809514cd7473f83d0c";

        vm.startPrank(operatorOne);
        vm.expectRevert(abi.encodeWithSignature("InvalidPublicKeys()"));
        stakingContract.addValidators(0, 10, publicKeys, signatures);
        vm.stopPrank();
    }

    function testAddValidatorsInvalidSignature() public {
        bytes
            memory publicKeys = hex"0c74b6d3d877bbb2083f1bcc83b302f3ed533eaf3cd39cff97daf2c7b9b776168481aa7b51778df673a37049886f25b07f03dbc79d85fa9d41f9eefa8e598353b652aadf497673744527c73127f872b91cf31ec8041dae1b3a4238683cf442ea23a95fe68b400ab42b14e8c99280a057d1d840e80723c3622b38e6acd1f471bf247cf62312c9b863a75ac0d270cefa4f84fd8586dbda15c67c1a46e85cf56c60550f54cb082770baf3d2bbf4c33f5254bd0b93e017f3ed036b13baec41bb69085f9eff48651be38c8f9e1f67b643f84ec356864aaa057f0042b121b9d040ed9be3f5cc9cc659d8f8fc02575ed3c25708adac2c8d0c50ab7e4599ce9edf300d98e1cfcfc8e0022a24c712f0769de99a3389bac1cdca92ae20fba323142fe2e8d09ef2cb59c3f822779b3fe6410cddce7255d35db01093cc435c0a35bbb4cd8d4eb3bd2cc597c49a7a909c16f67fe8b6702d5d0c22ad189b1c45325190015b0017606f768c7aa2006cc19dfeb5f367eae9dd17a5c307705db1f5cec552fc038e5fa3a76352d9621a4d74b1fd7e1707c7bfb5e912e2b5a33a2f34a419055d0c4065aa787f743aff953d73441e96ffc9b0f5a3248c23398518a758aec8451b626bff7eed063a3b11bf661d10ad6dac5ee62f47be125e3c668e14b3c704d736b4fbff";
        bytes
            memory signatures = hex"fe41ffbe702fb08d01063c9cd99fac11a16e921c784e681e365db00c4bd6760df67cfc0d0555a8ee8bf534a2c0987b7949b18dba726ced579240fa063274bc7ab25e44b758c452c433debfebbc075cbe105f07502402a9591dc891640a9f2b34fe0863bf987ff4b5a601b0ffcecc185f04847e0b97d3fb9457c32efb9c3ce35520308cfcc8ca78d5d4da164f6d1575d32fe466b8076bc4056ad97fa3e3607a60e5e420bdec413e5ffcc3119b1b89a957b14a437e009a858c4c40c0f1fc7f3d1ad83bc96ada6c2c772260637774e5fbdc60791db6de3a31e136c28106b35c21932a8ed610306f0723675730e31d3deceff4f912e6070c9efcd6e3f0c9ad4a0e203f437f21679b87d46351714b5a1b6226f8ffadd19e18f85c918461ab67291e1c8cdfdc05280adf2b923f1269cf7de8bd351a7ede13524e836cbfc7ba22db91aaa5c9a0729a469985f5bd844347ba9a9b4019f4ad42c2025457cf48557494ac3ce6e311a1ded3e903cd3009d18133015d445d02a3ce3858781b582d28701a311ddb271f8a0c91c65b32cc13c512c35e5be9bb9dc556dfd3249a3733f58426718974820f17b3242a089e29b129fcea37c8b84996e2c725b59efccee24068625584e583700346f823ce92e11ac9db5964ca6300905c5e9f294330037ec1cb7d9b8fc28829b98fcc0fc405afcd54f43cb4a14e8cab3f5aa979fe2c3492fe295e1a50170e8857bd94e5b009bcec9626e6eb137b272882037202da7329dadcb5b99bbd7835b8875d696dab41774dcb559bfb4c79a5337efc5f1606bc7c2752389a49b6a578f0c7c58e2bf9efc55eef19beaf3de94da90c712ca3891ac71a6ff6d778a1c0c31f77fdde2c4b7f29adf8ccf000050e9e4829d2de36fda8d6b26020e6f0ece339e9ad96c01b166301238e1aaa30ddfb978968361a5f9d3fcaa381973c967c0dd88c6d54d00fa375ab4df3be57c4360b69d7634e95e4d4201da8f2348d0ce53be690146f0049d5d173a635d21406b10ed23ec9996bd0a43b812df363986fb8dedf5be1cdb3f85a5090460511af617507d24657e3733310b42e1406070a0316620037da35c5227bb85d3aacf3aebf750265838994e03a8770cdc1c31723ca1037232c32d21f31eee561575b18b1b4c0f027f270898aed60ab4bfe41160cd989cd5bdfeb795097ff01cd0ff41fea96311e92798c0a619aa957772cfd408747fc30dcb39210839a4c70b87d3ad881207fa5eee926bc2c6936ce10b382c7a37606d40bb1cf2637768255aae4a4cd18ed7004e3046520bea92c66a7074e4b46d3d566703e44d0c3f9ef49a2ff30632fe3f6a409178db66423809514cd7473f83d";

        vm.startPrank(operatorOne);
        vm.expectRevert(abi.encodeWithSignature("InvalidSignatures()"));
        stakingContract.addValidators(0, 10, publicKeys, signatures);
        vm.stopPrank();
    }

    function testAddValidatorsUnauthorized() public {
        bytes
            memory publicKeys = hex"0c74b6d3d877bbb2083f1bcc83b302f3ed533eaf3cd39cff97daf2c7b9b776168481aa7b51778df673a37049886f25b07f03dbc79d85fa9d41f9eefa8e598353b652aadf497673744527c73127f872b91cf31ec8041dae1b3a4238683cf442ea23a95fe68b400ab42b14e8c99280a057d1d840e80723c3622b38e6acd1f471bf247cf62312c9b863a75ac0d270cefa4f84fd8586dbda15c67c1a46e85cf56c60550f54cb082770baf3d2bbf4c33f5254bd0b93e017f3ed036b13baec41bb69085f9eff48651be38c8f9e1f67b643f84ec356864aaa057f0042b121b9d040ed9be3f5cc9cc659d8f8fc02575ed3c25708adac2c8d0c50ab7e4599ce9edf300d98e1cfcfc8e0022a24c712f0769de99a3389bac1cdca92ae20fba323142fe2e8d09ef2cb59c3f822779b3fe6410cddce7255d35db01093cc435c0a35bbb4cd8d4eb3bd2cc597c49a7a909c16f67fe8b6702d5d0c22ad189b1c45325190015b0017606f768c7aa2006cc19dfeb5f367eae9dd17a5c307705db1f5cec552fc038e5fa3a76352d9621a4d74b1fd7e1707c7bfb5e912e2b5a33a2f34a419055d0c4065aa787f743aff953d73441e96ffc9b0f5a3248c23398518a758aec8451b626bff7eed063a3b11bf661d10ad6dac5ee62f47be125e3c668e14b3c704d736b4fbff";
        bytes
            memory signatures = hex"fe41ffbe702fb08d01063c9cd99fac11a16e921c784e681e365db00c4bd6760df67cfc0d0555a8ee8bf534a2c0987b7949b18dba726ced579240fa063274bc7ab25e44b758c452c433debfebbc075cbe105f07502402a9591dc891640a9f2b34fe0863bf987ff4b5a601b0ffcecc185f04847e0b97d3fb9457c32efb9c3ce35520308cfcc8ca78d5d4da164f6d1575d32fe466b8076bc4056ad97fa3e3607a60e5e420bdec413e5ffcc3119b1b89a957b14a437e009a858c4c40c0f1fc7f3d1ad83bc96ada6c2c772260637774e5fbdc60791db6de3a31e136c28106b35c21932a8ed610306f0723675730e31d3deceff4f912e6070c9efcd6e3f0c9ad4a0e203f437f21679b87d46351714b5a1b6226f8ffadd19e18f85c918461ab67291e1c8cdfdc05280adf2b923f1269cf7de8bd351a7ede13524e836cbfc7ba22db91aaa5c9a0729a469985f5bd844347ba9a9b4019f4ad42c2025457cf48557494ac3ce6e311a1ded3e903cd3009d18133015d445d02a3ce3858781b582d28701a311ddb271f8a0c91c65b32cc13c512c35e5be9bb9dc556dfd3249a3733f58426718974820f17b3242a089e29b129fcea37c8b84996e2c725b59efccee24068625584e583700346f823ce92e11ac9db5964ca6300905c5e9f294330037ec1cb7d9b8fc28829b98fcc0fc405afcd54f43cb4a14e8cab3f5aa979fe2c3492fe295e1a50170e8857bd94e5b009bcec9626e6eb137b272882037202da7329dadcb5b99bbd7835b8875d696dab41774dcb559bfb4c79a5337efc5f1606bc7c2752389a49b6a578f0c7c58e2bf9efc55eef19beaf3de94da90c712ca3891ac71a6ff6d778a1c0c31f77fdde2c4b7f29adf8ccf000050e9e4829d2de36fda8d6b26020e6f0ece339e9ad96c01b166301238e1aaa30ddfb978968361a5f9d3fcaa381973c967c0dd88c6d54d00fa375ab4df3be57c4360b69d7634e95e4d4201da8f2348d0ce53be690146f0049d5d173a635d21406b10ed23ec9996bd0a43b812df363986fb8dedf5be1cdb3f85a5090460511af617507d24657e3733310b42e1406070a0316620037da35c5227bb85d3aacf3aebf750265838994e03a8770cdc1c31723ca1037232c32d21f31eee561575b18b1b4c0f027f270898aed60ab4bfe41160cd989cd5bdfeb795097ff01cd0ff41fea96311e92798c0a619aa957772cfd408747fc30dcb39210839a4c70b87d3ad881207fa5eee926bc2c6936ce10b382c7a37606d40bb1cf2637768255aae4a4cd18ed7004e3046520bea92c66a7074e4b46d3d566703e44d0c3f9ef49a2ff30632fe3f6a409178db66423809514cd7473f83d0c";

        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        stakingContract.addValidators(0, 10, publicKeys, signatures);
    }

    function testRemoveValidatorsOperatorOne() public {
        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
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

        bytes
            memory pubKey = hex"fdca2994adc49ddccb195bda2510e50a4ae10de26cf96dee5e577689f51650a610a33da0a826ae47247d8d1189cb3386";
        assertTrue(stakingContract.getEnabledFromPublicKeyRoot(sha256(abi.encodePacked(pubKey, bytes16(0)))));

        vm.startPrank(operatorOne);
        vm.expectEmit(true, true, true, true);
        emit ValidatorKeyRemoved(0, pubKey);
        stakingContract.removeValidators(0, indexes);
        vm.stopPrank();

        assertFalse(stakingContract.getEnabledFromPublicKeyRoot(sha256(abi.encodePacked(pubKey, bytes16(0)))));

        (operatorAddress, feeRecipientAddress, limit, keys, funded, available, deactivated) = stakingContract
            .getOperator(0);

        assertEq(operatorAddress, operatorOne);
        assertEq(limit, 0);
        assertEq(keys, 0);
        assertEq(funded, 0);
        assertEq(available, 0);
        assert(deactivated == false);
    }

    function testRemoveValidatorsDeactivatedOperatorOne() public {
        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
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
        stakingContract.deactivateOperator(0, address(1));
        vm.stopPrank();

        vm.startPrank(operatorOne);
        vm.expectRevert(abi.encodeWithSignature("Deactivated()"));
        stakingContract.removeValidators(0, indexes);
        vm.stopPrank();

        (operatorAddress, feeRecipientAddress, limit, keys, funded, available, deactivated) = stakingContract
            .getOperator(0);

        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, address(1));
        assertEq(limit, 0);
        assertEq(keys, 10);
        assertEq(funded, 0);
        assertEq(available, 0);
        assert(deactivated == true);

        vm.startPrank(admin);
        stakingContract.removeValidators(0, indexes);
        vm.stopPrank();

        (operatorAddress, feeRecipientAddress, limit, keys, funded, available, deactivated) = stakingContract
            .getOperator(0);

        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, address(1));
        assertEq(limit, 0);
        assertEq(keys, 0);
        assertEq(funded, 0);
        assertEq(available, 0);
        assert(deactivated == true);
    }

    function testRemoveValidatorsOperatorOneInvalidIndexes() public {
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

        vm.startPrank(operatorOne);
        vm.expectRevert(abi.encodeWithSignature("UnsortedIndexes()"));
        stakingContract.removeValidators(0, indexes);
        vm.stopPrank();
    }

    function testRemoveValidatorsOperatorOneUnauthorized() public {
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
        stakingContract.removeValidators(0, indexes);
    }

    function testRemoveValidatorsWhileFunded(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
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

        vm.startPrank(operatorOne);
        stakingContract.removeValidators(0, indexes);
        vm.stopPrank();

        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 1);
        assertEq(keys, 1);
        assertEq(funded, 1);
        assertEq(available, 0);
        assert(deactivated == false);
    }

    function testRemoveFundedValidator(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
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

        vm.startPrank(operatorOne);
        vm.expectRevert(abi.encodeWithSignature("FundedValidatorDeletionAttempt()"));
        stakingContract.removeValidators(0, indexes);
        vm.stopPrank();
    }

    event SetWithdrawerCustomizationStatus(bool _status);

    function testSetWithdrawer(uint256 _userSalt, uint256 _anotherUserSalt) public {
        address user = uf._new(_userSalt);
        address anotherUser = uf._new(_anotherUserSalt);
        vm.deal(user, 32 * 3 ether);

        vm.startPrank(user);
        (bool _success, ) = address(stakingContract).call{value: 32 * 3 ether}("");
        assert(_success == true);
        vm.stopPrank();

        assertEq(user.balance, 0);

        bytes
            memory pk = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";

        assertEq(stakingContract.getWithdrawer(pk), user);

        vm.startPrank(admin);
        vm.expectEmit(true, true, true, true);
        emit SetWithdrawerCustomizationStatus(true);
        stakingContract.setWithdrawerCustomizationEnabled(true);
        vm.stopPrank();

        vm.startPrank(user);
        stakingContract.setWithdrawer(pk, anotherUser);
        vm.stopPrank();
    }

    function testSetWithdrawerForbidden(uint256 _userSalt, uint256 _anotherUserSalt) public {
        address user = uf._new(_userSalt);
        address anotherUser = uf._new(_anotherUserSalt);
        vm.deal(user, 32 * 3 ether);

        vm.startPrank(user);
        (bool _success, ) = address(stakingContract).call{value: 32 * 3 ether}("");
        assert(_success == true);
        vm.stopPrank();

        assertEq(user.balance, 0);

        bytes
            memory pk = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";

        assertEq(stakingContract.getWithdrawer(pk), user);

        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("Forbidden()"));
        stakingContract.setWithdrawer(pk, anotherUser);
        vm.stopPrank();
    }

    function testSetWithdrawerUnauthorized(uint256 _userSalt, uint256 _anotherUserSalt) public {
        address user = uf._new(_userSalt);
        address anotherUser = uf._new(_anotherUserSalt);
        vm.deal(user, 32 * 3 ether);

        vm.startPrank(user);
        (bool _success, ) = address(stakingContract).call{value: 32 * 3 ether}("");
        assert(_success == true);
        vm.stopPrank();

        assertEq(user.balance, 0);

        vm.startPrank(admin);
        stakingContract.setWithdrawerCustomizationEnabled(true);
        vm.stopPrank();

        bytes
            memory pk = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";

        assertEq(stakingContract.getWithdrawer(pk), user);

        vm.startPrank(anotherUser);
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        stakingContract.setWithdrawer(pk, anotherUser);
        vm.stopPrank();
    }

    event ChangedTreasury(address newTreasury);

    function testSetTreasury(uint256 _treasurySalt) public {
        address newTreasury = uf._new(_treasurySalt);
        vm.startPrank(admin);
        vm.expectEmit(true, true, true, true);
        emit ChangedTreasury(newTreasury);
        stakingContract.setTreasury(newTreasury);
        vm.stopPrank();

        address gotTreasury = stakingContract.getTreasury();
        assertEq(newTreasury, gotTreasury);
    }

    function testSetTreasuryUnauthorized(uint256 _userSalt) public {
        address user = uf._new(_userSalt);

        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        stakingContract.setTreasury(user);
        vm.stopPrank();
    }
}

contract StakingContractInitializationTest is DSTestPlus {
    Vm internal vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    address internal treasury;
    StakingContract internal stakingContract;
    DepositContractMock internal depositContract;
    UserFactory internal uf;

    address internal admin = address(1);

    bytes32 salt = bytes32(0);

    function setUp() public {
        uf = new UserFactory();
        address[] memory recipients = new address[](1);
        uint256[] memory percents = new uint256[](1);
        percents[0] = 10_000;
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

    function testAddOperator(uint256 _operatorSalt) public {
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
        address newOperator = uf._new(_operatorSalt);
        address newOperatorFeeRecipient = uf._new(_operatorSalt);

        uint256 operatorIndex;

        vm.startPrank(admin);
        vm.expectEmit(true, true, true, true);
        emit NewOperator(newOperator, newOperatorFeeRecipient, 0);
        operatorIndex = stakingContract.addOperator(newOperator, newOperatorFeeRecipient);
        vm.stopPrank();

        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        ) = stakingContract.getOperator(operatorIndex);
        assertEq(operatorAddress, newOperator);
        assertEq(feeRecipientAddress, newOperatorFeeRecipient);
        assertEq(limit, 0);
        assertEq(keys, 0);
        assertEq(funded, 0);
        assertEq(available, 0);
        assert(deactivated == false);
    }
}

contract StakingContractOperatorTest is DSTestPlus {
    Vm internal vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    address internal treasury;
    StakingContract internal stakingContract;
    DepositContractMock internal depositContract;
    UserFactory internal uf;

    address internal admin = address(1);

    bytes32 salt = bytes32(0);

    function setUp() public {
        uf = new UserFactory();
        address[] memory recipients = new address[](1);
        uint256[] memory percents = new uint256[](1);
        percents[0] = 10_000;
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

    function testAddOperatorLimitReached(uint128 _operatorSalt) public {
        vm.roll(uint256(_operatorSalt) + 1);
        uint256 operatorIndex = 0;
        address newOperator;
        address newOperatorFeeRecipient;

        vm.startPrank(admin);
        address operatorZero;
        // We register as much operator as possible.
        for (uint256 i = 0; i < 1; i++) {
            newOperator = uf._new(uint256(_operatorSalt) + (i * 2));
            if (i == 0) {
                operatorZero = newOperator;
            }
            newOperatorFeeRecipient = uf._new(uint256(_operatorSalt) + (i * 2) + 1);

            operatorIndex = stakingContract.addOperator(newOperator, newOperator);
            assertEq(i, operatorIndex);
        }

        bytes
            memory publicKeys = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e06014451b3fb9288549aff6dea9843b43e0c47a3b856f307732175230e254c0004e48b02414987088ac7003e148930017b49a1a8d4600f33d463c4afc07bbfc82703c9fcf81a5891f90a71c86a02faff443c6c3b2592bd44d5d3d7a93cb4aaaa105612496d61e68140a5418b468f872bf2f3e79f9cb0d9c3e889663fca02939b31e8ee3092203ee1417128e965c6406a07f68abf2ebe2689cf6c853ef126ffa8574c2a7d913e28de9147fa6b96706ea5bf9eacd1aba06edeaee155009fb912c00070774cc64136fcffde12ed731260bc5529df64da298f493561198e9d6acf42cf21e853ae7b2df85f27d2183149969d623b9237254c2cfe1d0082742eb042ac096d686dbe03c79ee31cbd03bb4682f8797043eed9f6e622814831ac5dfe1176552fb7f9b6ff38a149ae1d8414097a32fd96da6453c52fda13e3402a09e2fa6886daa4300f09c73e4bc2901b99c44744c5cfdca2994adc49ddccb195bda2510e50a4ae10de26cf96dee5e577689f51650a610a33da0a826ae47247d8d1189cb3386";

        bytes
            memory signatures = hex"ccb81f4485957f440bc17dbe760f374cbb112c6f12fa10e8709fac4522b30440d918c7bb867fa04f6b3cfbd977455f8f2fde586fdf3d7baa429e98e497ff871f3b8db1528b2b964fa24d26e377c74746496cc719c50dbf391fb3f74f5ca4b93a02a9f0007cd7b7d2af2d1b07c8600ab86a5d27dc51a29c2e3007c7a69cb73bcaecc764641e02370955dba100428d259d6475ee3566872bd43b0e73e55b9669e50f2b1666e57b326a5dfad655c7921e0dfb421b1ec59c8fdb48eb77421fd06966f393d619cbf13ff427df11dcb17026df25f35268de5b168e359c16f2a3d5fbc6376db44638d773c851c875f21222448433d285920e8bdc4f5cbff130d7387c0a9589324286aea398e5aacad3bbfe3992dfce62571f0e282ed9c29e3fa5b07aa5c81749589b1170d3b85a84331e2f6b8e26eadebfd569b225759f40bbd12d6c3d253ed3f379b014b2ea44cce54d362072e2d020ff139a903b7d87fc3fddc2e6657c83e0b79851c22c6e0e477463463c97d6cc0e2e2de5e35b227bddb285521be3766358abaf3159d89f68c9770e28278f177088cfc4089b817effaaecabdffa4e66427868b105cb9348ea2d84eeea059a5d1ff3277d6f9cf656fc973d07cabed70fb8f8eb2798a65d207a8e1f8a26910949db9fa62d62bc15ecc097a93a27a1873405b8589a4ddf0ecf0303c6031484562b32eb7881975026524d6d4a9de6cd73fe2c324501586b9b6fa6bce950bbd21472278302f83dbfd6be036f2fc36d299d66578e844be3d6aa8314fab468f038fd6e130ada0a886fccfb2fd843f7dd07e8968401bbe2af7345fce52ba4b310b30af2d54b15669d06c206682c1730ab6b17787e361f04401f78dc5cbd5fac955df4e83c24cdabfabdb3f4ea40961d04a5ca166c17694fca144025b47131a68ddb230d36fe6e831e82624c9a925d706bff86982852b26ebf019a3f6ee36aedbbc6bec2d50531a233e09225493d3c5fd48379aec373baf622fb9feed6261e5296e5ae6601e7523c7f386801ed63a344b07106a0d03e5848209db5e114c0e67884916a43a1bfb77d9b8ea113c3ba8cad4b006aafeadcc31e70e85c5efecaf807154d011c1413340d4b592d2f270fb48b2050e08493c1427ddfac8dcc27fe434d32a35dcbddbcb1c4e22ead6734a4ac910f6768bc9ff6b355c1151695e41121cdcc9d9d3b18cf4d66ca3c1db0527c471a0dcf256590602a7269dcb26175e7eb370bd9794ac8ab558bea69e6a92d8e818b675a80e2df0516b8307291d93cb85d959ac60d47b46455a7ab0a38687c747c6d2d9e8c20ccf74dc6cdf145ec06805d4ac24a39aec2f5cd6e26e63e3d043a31c42411e4";
        vm.stopPrank();
        vm.startPrank(operatorZero);
        stakingContract.addValidators(0, 10, publicKeys, signatures);
        vm.stopPrank();
        vm.startPrank(admin);
        stakingContract.setOperatorLimit(0, 10, block.number);
        vm.stopPrank();

        vm.deal(address(this), 32 ether);
        stakingContract.deposit{value: 32 ether}();

        vm.startPrank(admin);
        newOperator = uf._new(_operatorSalt);
        newOperatorFeeRecipient = uf._new(_operatorSalt);
        vm.expectRevert(abi.encodeWithSignature("MaximumOperatorCountAlreadyReached()"));
        operatorIndex = stakingContract.addOperator(newOperator, newOperatorFeeRecipient);
        vm.stopPrank();
    }
}

contract StakingContractDistributionTest is DSTestPlus {
    Vm internal vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    address internal treasury;
    StakingContract internal stakingContract;
    DepositContractMock internal depositContract;
    UserFactory internal uf;

    address internal admin = address(1);
    address internal bob = address(2);
    address internal alice = address(3);
    address[] internal operators;
    bytes32 salt = bytes32(0);

    function setUp() public {
        uf = new UserFactory();
        address[] memory recipients = new address[](1);
        uint256[] memory percents = new uint256[](1);
        percents[0] = 10_000;
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

        uint256 depositCount = (uint256(newOps) * uint256(keyPerOperator)) / 2;

        for (uint256 i; i < newOps; ++i) {
            vm.startPrank(admin);
            address newOperator = uf._new(uint256(keccak256(abi.encodePacked(i))));
            address newOperatorFeeRecipient = uf._new(uint256(keccak256(abi.encodePacked(i))));

            stakingContract.addOperator(newOperator, newOperatorFeeRecipient);
            operators.push(newOperator);
            vm.stopPrank();
            vm.startPrank(newOperator);
            bytes memory publicKeys = genBytes(uint256(keyPerOperator) * 48);
            bytes memory signatures = genBytes(uint256(keyPerOperator) * 96);
            stakingContract.addValidators(i, keyPerOperator, publicKeys, signatures);
            vm.stopPrank();
            vm.startPrank(admin);
            stakingContract.setOperatorLimit(i, keyPerOperator, block.number);
            vm.stopPrank();
        }

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
    address internal treasury;
    StakingContract internal stakingContract;
    DepositContractMock internal depositContract;
    UserFactory internal uf;

    address internal admin = address(1);
    address internal bob = address(2);
    address internal alice = address(3);
    address internal operatorOne = address(4);
    address internal feeRecipientOne = address(44);
    ExecutionLayerFeeDispatcher internal eld;
    ConsensusLayerFeeDispatcher internal cld;
    FeeRecipient internal feeRecipientImpl;

    function setUp() public {
        uf = new UserFactory();
        address[] memory recipients = new address[](1);
        uint256[] memory percents = new uint256[](1);
        percents[0] = 10_000;
        treasury = address(99);
        stakingContract = new StakingContract();
        depositContract = new DepositContractMock();
        feeRecipientImpl = new FeeRecipient();

        address eldImpl = address(new ExecutionLayerFeeDispatcher(1));
        address cldImpl = address(new ConsensusLayerFeeDispatcher(1));

        eld = ExecutionLayerFeeDispatcher(
            payable(
                address(new TUPProxy(eldImpl, address(1), abi.encodeWithSignature("initELD(address)", stakingContract)))
            )
        );

        cld = ConsensusLayerFeeDispatcher(
            payable(
                address(new TUPProxy(cldImpl, address(1), abi.encodeWithSignature("initCLD(address)", stakingContract)))
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
        stakingContract.addOperator(operatorOne, feeRecipientOne);
        vm.stopPrank();

        {
            bytes
                memory publicKeys = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e06014451b3fb9288549aff6dea9843b43e0c47a3b856f307732175230e254c0004e48b02414987088ac7003e148930017b49a1a8d4600f33d463c4afc07bbfc82703c9fcf81a5891f90a71c86a02faff443c6c3b2592bd44d5d3d7a93cb4aaaa105612496d61e68140a5418b468f872bf2f3e79f9cb0d9c3e889663fca02939b31e8ee3092203ee1417128e965c6406a07f68abf2ebe2689cf6c853ef126ffa8574c2a7d913e28de9147fa6b96706ea5bf9eacd1aba06edeaee155009fb912c00070774cc64136fcffde12ed731260bc5529df64da298f493561198e9d6acf42cf21e853ae7b2df85f27d2183149969d623b9237254c2cfe1d0082742eb042ac096d686dbe03c79ee31cbd03bb4682f8797043eed9f6e622814831ac5dfe1176552fb7f9b6ff38a149ae1d8414097a32fd96da6453c52fda13e3402a09e2fa6886daa4300f09c73e4bc2901b99c44744c5cfdca2994adc49ddccb195bda2510e50a4ae10de26cf96dee5e577689f51650a610a33da0a826ae47247d8d1189cb3386";

            bytes
                memory signatures = hex"ccb81f4485957f440bc17dbe760f374cbb112c6f12fa10e8709fac4522b30440d918c7bb867fa04f6b3cfbd977455f8f2fde586fdf3d7baa429e98e497ff871f3b8db1528b2b964fa24d26e377c74746496cc719c50dbf391fb3f74f5ca4b93a02a9f0007cd7b7d2af2d1b07c8600ab86a5d27dc51a29c2e3007c7a69cb73bcaecc764641e02370955dba100428d259d6475ee3566872bd43b0e73e55b9669e50f2b1666e57b326a5dfad655c7921e0dfb421b1ec59c8fdb48eb77421fd06966f393d619cbf13ff427df11dcb17026df25f35268de5b168e359c16f2a3d5fbc6376db44638d773c851c875f21222448433d285920e8bdc4f5cbff130d7387c0a9589324286aea398e5aacad3bbfe3992dfce62571f0e282ed9c29e3fa5b07aa5c81749589b1170d3b85a84331e2f6b8e26eadebfd569b225759f40bbd12d6c3d253ed3f379b014b2ea44cce54d362072e2d020ff139a903b7d87fc3fddc2e6657c83e0b79851c22c6e0e477463463c97d6cc0e2e2de5e35b227bddb285521be3766358abaf3159d89f68c9770e28278f177088cfc4089b817effaaecabdffa4e66427868b105cb9348ea2d84eeea059a5d1ff3277d6f9cf656fc973d07cabed70fb8f8eb2798a65d207a8e1f8a26910949db9fa62d62bc15ecc097a93a27a1873405b8589a4ddf0ecf0303c6031484562b32eb7881975026524d6d4a9de6cd73fe2c324501586b9b6fa6bce950bbd21472278302f83dbfd6be036f2fc36d299d66578e844be3d6aa8314fab468f038fd6e130ada0a886fccfb2fd843f7dd07e8968401bbe2af7345fce52ba4b310b30af2d54b15669d06c206682c1730ab6b17787e361f04401f78dc5cbd5fac955df4e83c24cdabfabdb3f4ea40961d04a5ca166c17694fca144025b47131a68ddb230d36fe6e831e82624c9a925d706bff86982852b26ebf019a3f6ee36aedbbc6bec2d50531a233e09225493d3c5fd48379aec373baf622fb9feed6261e5296e5ae6601e7523c7f386801ed63a344b07106a0d03e5848209db5e114c0e67884916a43a1bfb77d9b8ea113c3ba8cad4b006aafeadcc31e70e85c5efecaf807154d011c1413340d4b592d2f270fb48b2050e08493c1427ddfac8dcc27fe434d32a35dcbddbcb1c4e22ead6734a4ac910f6768bc9ff6b355c1151695e41121cdcc9d9d3b18cf4d66ca3c1db0527c471a0dcf256590602a7269dcb26175e7eb370bd9794ac8ab558bea69e6a92d8e818b675a80e2df0516b8307291d93cb85d959ac60d47b46455a7ab0a38687c747c6d2d9e8c20ccf74dc6cdf145ec06805d4ac24a39aec2f5cd6e26e63e3d043a31c42411e4";

            vm.startPrank(operatorOne);
            stakingContract.addValidators(0, 10, publicKeys, signatures);
            vm.stopPrank();
        }

        {
            vm.startPrank(admin);
            stakingContract.setOperatorLimit(0, 10, block.number);
            vm.stopPrank();
        }
    }

    event Deposit(address indexed caller, address indexed withdrawer, bytes publicKey, bytes signature);
    event DepositEvent(bytes pubkey, bytes withdrawal_credentials, bytes amount, bytes signature, bytes index);

    function testExplicitDepositOneValidatorCheckDepositEvent(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 32 ether);

        vm.startPrank(user);
        bytes memory expectedWithdrawalCredentials = abi.encodePacked(
            bytes32(
                uint256(
                    uint160(
                        stakingContract.getCLFeeRecipient(
                            hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759"
                        )
                    )
                ) + 0x0100000000000000000000000000000000000000000000000000000000000000
            )
        );
        vm.expectEmit(true, true, true, true);
        emit DepositEvent(
            hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759",
            expectedWithdrawalCredentials,
            hex"0040597307000000",
            hex"ccb81f4485957f440bc17dbe760f374cbb112c6f12fa10e8709fac4522b30440d918c7bb867fa04f6b3cfbd977455f8f2fde586fdf3d7baa429e98e497ff871f3b8db1528b2b964fa24d26e377c74746496cc719c50dbf391fb3f74f5ca4b93a",
            hex"0000000000000000"
        );
        stakingContract.deposit{value: 32 ether}();
        vm.stopPrank();

        assertEq(user.balance, 0);

        (, , uint256 limit, uint256 keys, uint256 funded, uint256 available, bool deactivated) = stakingContract
            .getOperator(0);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 1);
        assertEq(available, 9);
        assert(deactivated == false);
    }

    function testExplicitDepositOneValidator(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 32 ether);

        vm.startPrank(user);
        stakingContract.deposit{value: 32 ether}();
        vm.stopPrank();

        assertEq(user.balance, 0);

        (, , uint256 limit, uint256 keys, uint256 funded, uint256 available, bool deactivated) = stakingContract
            .getOperator(0);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 1);
        assertEq(available, 9);
        assert(deactivated == false);
    }

    function testExplicitDepositTwoValidators(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 32 * 2 ether);

        vm.startPrank(user);
        vm.expectEmit(true, true, true, true);
        emit Deposit(
            user,
            user,
            hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060",
            hex"02a9f0007cd7b7d2af2d1b07c8600ab86a5d27dc51a29c2e3007c7a69cb73bcaecc764641e02370955dba100428d259d6475ee3566872bd43b0e73e55b9669e50f2b1666e57b326a5dfad655c7921e0dfb421b1ec59c8fdb48eb77421fd06966"
        );
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
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 2);
        assertEq(available, 8);
        assert(deactivated == false);
    }

    function testExplicitDepositAllValidators(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
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
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 10);
        assertEq(available, 0);
        assert(deactivated == false);
    }

    function testExplicitDepositNotEnough(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 32 * 11 ether);

        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("NotEnoughValidators()"));
        stakingContract.deposit{value: 32 * 11 ether}();
        vm.stopPrank();
    }

    function testExplicitDepositNotEnoughAfterFilled(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 32 * 11 ether);

        vm.startPrank(user);
        stakingContract.deposit{value: 32 * 10 ether}();
        vm.stopPrank();
        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("NotEnoughValidators()"));
        stakingContract.deposit{value: 32 ether}();
        vm.stopPrank();
    }

    function testExplicitDepositInvalidAmount(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 31.9 ether);

        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("InvalidDepositValue()"));
        stakingContract.deposit{value: 31.9 ether}();
        vm.stopPrank();
    }

    function testImplicitDepositOneValidator(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 32 ether);

        vm.startPrank(user);
        (bool _success, ) = address(stakingContract).call{value: 32 ether}("");
        assert(_success == true);
        vm.stopPrank();

        assertEq(user.balance, 0);

        (, , uint256 limit, uint256 keys, uint256 funded, uint256 available, bool deactivated) = stakingContract
            .getOperator(0);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 1);
        assertEq(available, 9);
        assert(deactivated == false);
    }

    function testImplicitDepositTwoValidators(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 32 * 2 ether);

        vm.startPrank(user);
        vm.expectEmit(true, true, true, true);
        emit Deposit(
            user,
            user,
            hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060",
            hex"02a9f0007cd7b7d2af2d1b07c8600ab86a5d27dc51a29c2e3007c7a69cb73bcaecc764641e02370955dba100428d259d6475ee3566872bd43b0e73e55b9669e50f2b1666e57b326a5dfad655c7921e0dfb421b1ec59c8fdb48eb77421fd06966"
        );
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
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 2);
        assertEq(available, 8);
        assert(deactivated == false);
    }

    function testImplicitDepositAllValidators(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
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
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 10);
        assertEq(available, 0);
        assert(deactivated == false);
    }

    function testImplicitDepositNotEnough(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 32 * 11 ether);

        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("NotEnoughValidators()"));
        (bool _success, ) = address(stakingContract).call{value: 32 * 11 ether}("");
        assert(_success == true);
        vm.stopPrank();
    }

    function testImplicitDepositNotEnoughAfterFilled(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
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

    function testImplicitDepositInvalidAmount(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
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
    }

    function testFeeRecipients() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        address _elfr = stakingContract.getELFeeRecipient(publicKey);
        address _clfr = stakingContract.getCLFeeRecipient(publicKey);
        assert(_elfr != _clfr);
    }

    function testWithdrawELFees() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(publicKey);
        assert(elfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);
        vm.deal(address(elfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.withdrawELFee(publicKey);
        assert(elfrBob.code.length != 0);
        assert(bob.balance == 0.9 ether);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0.02 ether);
        assert(address(treasury).balance == 0.08 ether);
    }

    function testWithdrawELFees_asAdmin() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(publicKey);
        assert(elfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);
        vm.deal(address(elfrBob), 1 ether);
        vm.prank(admin);
        stakingContract.withdrawELFee(publicKey);
        assert(elfrBob.code.length != 0);
        assert(bob.balance == 0.9 ether);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0.02 ether);
        assert(address(treasury).balance == 0.08 ether);
    }

    function testWithdrawELFees_asRandom() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(publicKey);
        assert(elfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);
        vm.deal(address(elfrBob), 1 ether);
        vm.expectRevert(abi.encodeWithSignature("InvalidWithdrawer()"));
        vm.prank(address(0xdede));
        stakingContract.withdrawELFee(publicKey);
    }

    function testWithdrawELFeesEditedOperatorFee() public {
        vm.startPrank(admin);
        stakingContract.setOperatorFee(5000);
        vm.stopPrank();
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(publicKey);
        assert(elfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);
        assert(address(treasury).balance == 0);
        vm.deal(address(elfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.withdrawELFee(publicKey);
        assert(elfrBob.code.length != 0);
        assert(bob.balance == 0.9 ether);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0.05 ether);
        assert(address(treasury).balance == 0.05 ether);
    }

    function testWithdrawELFeesAlreadyDeployed() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(publicKey);
        assert(elfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);
        vm.deal(address(elfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.withdrawELFee(publicKey);
        assert(elfrBob.code.length != 0);
        assert(bob.balance == 0.9 ether);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0.02 ether);
        assert(address(treasury).balance == 0.08 ether);
        vm.deal(address(elfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.withdrawELFee(publicKey);
        assert(bob.balance == 1.8 ether);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0.04 ether);
        assert(address(treasury).balance == 0.16 ether);
    }

    function testWithdrawELFeesEmptyWithdrawal() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.expectRevert(abi.encodeWithSignature("ZeroBalanceWithdrawal()"));
        stakingContract.withdrawELFee(publicKey);
    }

    function testWithdrawCLFeesExitedValidator() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(address(treasury).balance == 0 ether);
        assert(feeRecipientOne.balance == 0);
        vm.deal(address(clfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.requestValidatorsExit(publicKey);
        vm.deal(address(clfrBob), 33 ether);
        vm.prank(bob);
        stakingContract.withdrawCLFee(publicKey);
        assert(clfrBob.code.length != 0);
        assertApproxEqAbs(bob.balance, 32.90 ether, 10**5);
        assertEq(operatorOne.balance, 0);
        assertApproxEqAbs(address(treasury).balance, 0.08 ether, 10**5);
        assertApproxEqAbs(feeRecipientOne.balance, 0.02 ether, 10**5);
    }

    function testWithdrawCLFeesEditedOperatorFee() public {
        vm.startPrank(admin);
        stakingContract.setOperatorFee(5000);
        vm.stopPrank();
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);
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
        assertEq(operatorOne.balance, 0);
        assertApproxEqAbs(feeRecipientOne.balance, 0.05 ether, 10**6);
    }

    function testWithdrawCLFeesSkimmedValidator() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);
        assert(address(treasury).balance == 0);
        vm.deal(address(clfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.withdrawCLFee(publicKey);
        assert(clfrBob.code.length != 0);
        assertApproxEqAbs(bob.balance, 0.90 ether, 10**6);
        assertApproxEqAbs(address(treasury).balance, 0.08 ether, 10**6);
        assertEq(operatorOne.balance, 0);
        assertApproxEqAbs(feeRecipientOne.balance, 0.02 ether, 10**6);
    }

    function testWithdrawCLFeesSkimmedLuckyValidator() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);
        assert(address(treasury).balance == 0);
        vm.deal(address(clfrBob), 2 ether);
        vm.prank(bob);
        stakingContract.withdrawCLFee(publicKey);
        assert(clfrBob.code.length != 0);
        assertApproxEqAbs(bob.balance, 1.8 ether, 10**6);
        assertApproxEqAbs(address(treasury).balance, 0.16 ether, 10**6);
        assertEq(operatorOne.balance, 0);
        assertApproxEqAbs(feeRecipientOne.balance, 0.04 ether, 10**6);
    }

    function testWithdrawCLFeesSlashedValidator() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        vm.deal(address(clfrBob), 1 ether); // 1 ETH skimmed
        vm.deal(address(clfrBob), 32 ether); // 31 ETH forced exit after slashing, exit not requested
        vm.prank(bob);
        stakingContract.withdrawCLFee(publicKey);
        assert(clfrBob.code.length != 0);
        // In this case bob would be manually rebated, including the commission charged on it's principal
        assertApproxEqAbs(bob.balance, 28.8 ether, 1);
        assertApproxEqAbs(address(treasury).balance, 2.56 ether, 10**6);
        assertApproxEqAbs(feeRecipientOne.balance, 0.64 ether, 10**6);
    }

    function testWithdrawCLFeesAlreadyDeployed() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);

        vm.deal(address(clfrBob), 1 ether);
        vm.prank(bob);

        stakingContract.withdrawCLFee(publicKey);

        assert(clfrBob.code.length != 0);
        assertApproxEqAbs(bob.balance, 0.90 ether, 10**6);
        assertApproxEqAbs(address(treasury).balance, 0.08 ether, 10**6);
        assertEq(operatorOne.balance, 0);
        assertApproxEqAbs(feeRecipientOne.balance, 0.02 ether, 10**6);

        vm.deal(address(clfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.requestValidatorsExit(publicKey);
        vm.deal(address(clfrBob), 33 ether);
        vm.prank(bob);
        stakingContract.withdrawCLFee(publicKey);

        assertApproxEqAbs(bob.balance, 33.80 ether, 10**6);
        assertApproxEqAbs(address(treasury).balance, 0.16 ether, 10**6);
        assertEq(operatorOne.balance, 0);
        assertApproxEqAbs(feeRecipientOne.balance, 0.04 ether, 10**6);
    }

    function testWithdrawCLFeesEmptyWithdrawal() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.expectRevert(abi.encodeWithSignature("ZeroBalanceWithdrawal()"));
        stakingContract.withdrawCLFee(publicKey);
        vm.stopPrank();
    }

    function testWithdrawAllFees() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();

        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);

        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);
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
        assertEq(operatorOne.balance, 0);
        assertApproxEqAbs(feeRecipientOne.balance, 0.04 ether, 10**6);
    }
}

contract StakingContractBehindProxyTest is Test {
    address internal treasury;
    StakingContract internal stakingContract;
    DepositContractMock internal depositContract;
    UserFactory internal uf;

    address internal admin = address(1);
    address internal bob = address(2);
    address internal alice = address(3);
    address internal operatorOne = address(4);
    address internal feeRecipientOne = address(44);
    ExecutionLayerFeeDispatcher internal eld;
    ConsensusLayerFeeDispatcher internal cld;
    FeeRecipient internal feeRecipientImpl;

    event ExitRequest(address caller, bytes pubkey);

    function setUp() public {
        uf = new UserFactory();
        depositContract = new DepositContractMock();
        feeRecipientImpl = new FeeRecipient();
        address[] memory recipients = new address[](1);
        uint256[] memory percents = new uint256[](1);
        percents[0] = 10_000;
        treasury = address(99);
        address eldImpl = address(new ExecutionLayerFeeDispatcher(1));
        address cldImpl = address(new ConsensusLayerFeeDispatcher(1));
        address stakingContractImpl = address(new StakingContract());

        stakingContract = StakingContract(payable(address(new TUPProxy(stakingContractImpl, address(12345), ""))));

        eld = ExecutionLayerFeeDispatcher(
            payable(
                address(new TUPProxy(eldImpl, address(1), abi.encodeWithSignature("initELD(address)", stakingContract)))
            )
        );

        cld = ConsensusLayerFeeDispatcher(
            payable(
                address(new TUPProxy(cldImpl, address(1), abi.encodeWithSignature("initCLD(address)", stakingContract)))
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
        stakingContract.addOperator(operatorOne, feeRecipientOne);
        vm.stopPrank();

        {
            bytes
                memory publicKeys = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e06014451b3fb9288549aff6dea9843b43e0c47a3b856f307732175230e254c0004e48b02414987088ac7003e148930017b49a1a8d4600f33d463c4afc07bbfc82703c9fcf81a5891f90a71c86a02faff443c6c3b2592bd44d5d3d7a93cb4aaaa105612496d61e68140a5418b468f872bf2f3e79f9cb0d9c3e889663fca02939b31e8ee3092203ee1417128e965c6406a07f68abf2ebe2689cf6c853ef126ffa8574c2a7d913e28de9147fa6b96706ea5bf9eacd1aba06edeaee155009fb912c00070774cc64136fcffde12ed731260bc5529df64da298f493561198e9d6acf42cf21e853ae7b2df85f27d2183149969d623b9237254c2cfe1d0082742eb042ac096d686dbe03c79ee31cbd03bb4682f8797043eed9f6e622814831ac5dfe1176552fb7f9b6ff38a149ae1d8414097a32fd96da6453c52fda13e3402a09e2fa6886daa4300f09c73e4bc2901b99c44744c5cfdca2994adc49ddccb195bda2510e50a4ae10de26cf96dee5e577689f51650a610a33da0a826ae47247d8d1189cb3386";

            bytes
                memory signatures = hex"ccb81f4485957f440bc17dbe760f374cbb112c6f12fa10e8709fac4522b30440d918c7bb867fa04f6b3cfbd977455f8f2fde586fdf3d7baa429e98e497ff871f3b8db1528b2b964fa24d26e377c74746496cc719c50dbf391fb3f74f5ca4b93a02a9f0007cd7b7d2af2d1b07c8600ab86a5d27dc51a29c2e3007c7a69cb73bcaecc764641e02370955dba100428d259d6475ee3566872bd43b0e73e55b9669e50f2b1666e57b326a5dfad655c7921e0dfb421b1ec59c8fdb48eb77421fd06966f393d619cbf13ff427df11dcb17026df25f35268de5b168e359c16f2a3d5fbc6376db44638d773c851c875f21222448433d285920e8bdc4f5cbff130d7387c0a9589324286aea398e5aacad3bbfe3992dfce62571f0e282ed9c29e3fa5b07aa5c81749589b1170d3b85a84331e2f6b8e26eadebfd569b225759f40bbd12d6c3d253ed3f379b014b2ea44cce54d362072e2d020ff139a903b7d87fc3fddc2e6657c83e0b79851c22c6e0e477463463c97d6cc0e2e2de5e35b227bddb285521be3766358abaf3159d89f68c9770e28278f177088cfc4089b817effaaecabdffa4e66427868b105cb9348ea2d84eeea059a5d1ff3277d6f9cf656fc973d07cabed70fb8f8eb2798a65d207a8e1f8a26910949db9fa62d62bc15ecc097a93a27a1873405b8589a4ddf0ecf0303c6031484562b32eb7881975026524d6d4a9de6cd73fe2c324501586b9b6fa6bce950bbd21472278302f83dbfd6be036f2fc36d299d66578e844be3d6aa8314fab468f038fd6e130ada0a886fccfb2fd843f7dd07e8968401bbe2af7345fce52ba4b310b30af2d54b15669d06c206682c1730ab6b17787e361f04401f78dc5cbd5fac955df4e83c24cdabfabdb3f4ea40961d04a5ca166c17694fca144025b47131a68ddb230d36fe6e831e82624c9a925d706bff86982852b26ebf019a3f6ee36aedbbc6bec2d50531a233e09225493d3c5fd48379aec373baf622fb9feed6261e5296e5ae6601e7523c7f386801ed63a344b07106a0d03e5848209db5e114c0e67884916a43a1bfb77d9b8ea113c3ba8cad4b006aafeadcc31e70e85c5efecaf807154d011c1413340d4b592d2f270fb48b2050e08493c1427ddfac8dcc27fe434d32a35dcbddbcb1c4e22ead6734a4ac910f6768bc9ff6b355c1151695e41121cdcc9d9d3b18cf4d66ca3c1db0527c471a0dcf256590602a7269dcb26175e7eb370bd9794ac8ab558bea69e6a92d8e818b675a80e2df0516b8307291d93cb85d959ac60d47b46455a7ab0a38687c747c6d2d9e8c20ccf74dc6cdf145ec06805d4ac24a39aec2f5cd6e26e63e3d043a31c42411e4";

            vm.startPrank(operatorOne);
            stakingContract.addValidators(0, 10, publicKeys, signatures);
            vm.stopPrank();
        }

        {
            vm.startPrank(admin);
            stakingContract.setOperatorLimit(0, 10, block.number);
            vm.stopPrank();
        }
    }

    event Deposit(address indexed caller, address indexed withdrawer, bytes publicKey, bytes signature);
    event DepositEvent(bytes pubkey, bytes withdrawal_credentials, bytes amount, bytes signature, bytes index);

    function testExplicitDepositOneValidatorCheckDepositEvent(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 32 ether);

        vm.startPrank(user);
        bytes memory expectedWithdrawalCredentials = abi.encodePacked(
            bytes32(
                uint256(
                    uint160(
                        stakingContract.getCLFeeRecipient(
                            hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759"
                        )
                    )
                ) + 0x0100000000000000000000000000000000000000000000000000000000000000
            )
        );
        vm.expectEmit(true, true, true, true);
        emit DepositEvent(
            hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759",
            expectedWithdrawalCredentials,
            hex"0040597307000000",
            hex"ccb81f4485957f440bc17dbe760f374cbb112c6f12fa10e8709fac4522b30440d918c7bb867fa04f6b3cfbd977455f8f2fde586fdf3d7baa429e98e497ff871f3b8db1528b2b964fa24d26e377c74746496cc719c50dbf391fb3f74f5ca4b93a",
            hex"0000000000000000"
        );
        stakingContract.deposit{value: 32 ether}();
        vm.stopPrank();

        assertEq(user.balance, 0);

        (, , uint256 limit, uint256 keys, uint256 funded, uint256 available, bool deactivated) = stakingContract
            .getOperator(0);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 1);
        assertEq(available, 9);
        assert(deactivated == false);
    }

    function testExplicitDepositOneValidator(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 32 ether);

        vm.startPrank(user);
        stakingContract.deposit{value: 32 ether}();
        vm.stopPrank();

        assertEq(user.balance, 0);

        (, , uint256 limit, uint256 keys, uint256 funded, uint256 available, bool deactivated) = stakingContract
            .getOperator(0);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 1);
        assertEq(available, 9);
        assert(deactivated == false);
    }

    function testExplicitDepositTwoValidators(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 32 * 2 ether);

        vm.startPrank(user);
        vm.expectEmit(true, true, true, true);
        emit Deposit(
            user,
            user,
            hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060",
            hex"02a9f0007cd7b7d2af2d1b07c8600ab86a5d27dc51a29c2e3007c7a69cb73bcaecc764641e02370955dba100428d259d6475ee3566872bd43b0e73e55b9669e50f2b1666e57b326a5dfad655c7921e0dfb421b1ec59c8fdb48eb77421fd06966"
        );
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
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 2);
        assertEq(available, 8);
        assert(deactivated == false);
    }

    function testExplicitDepositAllValidators(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
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
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 10);
        assertEq(available, 0);
        assert(deactivated == false);
    }

    function testExplicitDepositNotEnough(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 32 * 11 ether);

        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("NotEnoughValidators()"));
        stakingContract.deposit{value: 32 * 11 ether}();
        vm.stopPrank();
    }

    function testExplicitDepositNotEnoughAfterFilled(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 32 * 11 ether);

        vm.startPrank(user);
        stakingContract.deposit{value: 32 * 10 ether}();
        vm.stopPrank();
        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("NotEnoughValidators()"));
        stakingContract.deposit{value: 32 ether}();
        vm.stopPrank();
    }

    function testExplicitDepositInvalidAmount(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 31.9 ether);

        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("InvalidDepositValue()"));
        stakingContract.deposit{value: 31.9 ether}();
        vm.stopPrank();
    }

    function testImplicitDepositOneValidator(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 32 ether);

        vm.startPrank(user);
        (bool _success, ) = address(stakingContract).call{value: 32 ether}("");
        assert(_success == true);
        vm.stopPrank();

        assertEq(user.balance, 0);

        (, , uint256 limit, uint256 keys, uint256 funded, uint256 available, bool deactivated) = stakingContract
            .getOperator(0);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 1);
        assertEq(available, 9);
        assert(deactivated == false);
    }

    function testImplicitDepositTwoValidators(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 32 * 2 ether);

        vm.startPrank(user);
        vm.expectEmit(true, true, true, true);
        emit Deposit(
            user,
            user,
            hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060",
            hex"02a9f0007cd7b7d2af2d1b07c8600ab86a5d27dc51a29c2e3007c7a69cb73bcaecc764641e02370955dba100428d259d6475ee3566872bd43b0e73e55b9669e50f2b1666e57b326a5dfad655c7921e0dfb421b1ec59c8fdb48eb77421fd06966"
        );
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
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 2);
        assertEq(available, 8);
        assert(deactivated == false);
    }

    function testImplicitDepositAllValidators(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
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
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 10);
        assertEq(available, 0);
        assert(deactivated == false);
    }

    function testImplicitDepositNotEnough(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 32 * 11 ether);

        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("NotEnoughValidators()"));
        (bool _success, ) = address(stakingContract).call{value: 32 * 11 ether}("");
        assert(_success == true);
        vm.stopPrank();
    }

    function testImplicitDepositNotEnoughAfterFilled(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
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

    function testImplicitDepositInvalidAmount(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
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
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        address _elfr = stakingContract.getELFeeRecipient(publicKey);
        address _clfr = stakingContract.getCLFeeRecipient(publicKey);
        assert(_elfr != _clfr);
    }

    function testWithdrawELFees() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(publicKey);
        assert(elfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);
        vm.deal(address(elfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.withdrawELFee(publicKey);
        assert(elfrBob.code.length != 0);
        assert(bob.balance == 0.9 ether);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0.02 ether);
        assert(address(treasury).balance == 0.08 ether);
    }

    function testBatchWithdrawELFees() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        bytes
            memory publicKey2 = hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060";
        vm.deal(bob, 64 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey2) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(publicKey);
        address elfrBob2 = stakingContract.getELFeeRecipient(publicKey2);
        bytes memory publicKeys = BytesLib.concat(publicKey, publicKey2);
        vm.deal(address(elfrBob), 1 ether);
        vm.deal(address(elfrBob2), 1 ether);
        vm.prank(bob);
        stakingContract.batchWithdrawELFee(publicKeys);
        assert(bob.balance == 1.8 ether);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0.04 ether);
        assert(address(treasury).balance == 0.16 ether);
    }

    function testBatchWithdrawELFees_asAdmin() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        bytes
            memory publicKey2 = hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060";
        vm.deal(bob, 64 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey2) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(publicKey);
        address elfrBob2 = stakingContract.getELFeeRecipient(publicKey2);
        bytes memory publicKeys = BytesLib.concat(publicKey, publicKey2);
        vm.deal(address(elfrBob), 1 ether);
        vm.deal(address(elfrBob2), 1 ether);
        vm.prank(admin);
        stakingContract.batchWithdrawELFee(publicKeys);
        assert(bob.balance == 1.8 ether);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0.04 ether);
        assert(address(treasury).balance == 0.16 ether);
    }

    function testBatchWithdrawELFees_WrongWithdrawerSecondKey() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        bytes
            memory publicKey2 = hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060";
        vm.deal(bob, 32 ether);
        address bob2 = makeAddr("bob2");
        vm.deal(bob2, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        vm.prank(bob2);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey2) == bob2);
        address elfrBob = stakingContract.getELFeeRecipient(publicKey);
        address elfrBob2 = stakingContract.getELFeeRecipient(publicKey2);
        bytes memory publicKeys = BytesLib.concat(publicKey, publicKey2);
        vm.deal(address(elfrBob), 1 ether);
        vm.deal(address(elfrBob2), 1 ether);
        vm.expectRevert(abi.encodeWithSignature("InvalidWithdrawer()"));
        vm.prank(bob);
        stakingContract.batchWithdrawELFee(publicKeys);
    }

    function testBatchWithdrawELFees_WrongPublicKeys() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        bytes
            memory publicKey2 = hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060";
        vm.deal(bob, 64 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey2) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(publicKey);
        address elfrBob2 = stakingContract.getELFeeRecipient(publicKey2);
        bytes memory publicKeys = BytesLib.concat(publicKey, publicKey2);
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
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(publicKey);
        assert(elfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);
        assert(address(treasury).balance == 0);
        vm.deal(address(elfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.withdrawELFee(publicKey);
        assert(elfrBob.code.length != 0);
        assert(bob.balance == 0.9 ether);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0.05 ether);
        assert(address(treasury).balance == 0.05 ether);
    }

    function testWithdrawELFeesAlreadyDeployed() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(publicKey);
        assert(elfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);
        vm.deal(address(elfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.withdrawELFee(publicKey);
        assert(elfrBob.code.length != 0);
        assert(bob.balance == 0.9 ether);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0.02 ether);
        assert(address(treasury).balance == 0.08 ether);
        vm.deal(address(elfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.withdrawELFee(publicKey);
        assert(bob.balance == 1.8 ether);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0.04 ether);
        assert(address(treasury).balance == 0.16 ether);
    }

    function testWithdrawELFeesEmptyWithdrawal() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        vm.expectRevert(abi.encodeWithSignature("ZeroBalanceWithdrawal()"));
        vm.prank(bob);
        stakingContract.withdrawELFee(publicKey);
    }

    function testWithdrawCLFeesExitedValidator() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(address(treasury).balance == 0 ether);
        assert(feeRecipientOne.balance == 0);
        vm.deal(address(clfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.requestValidatorsExit(publicKey);
        vm.deal(address(clfrBob), 33 ether);
        vm.prank(bob);
        stakingContract.withdrawCLFee(publicKey);
        assert(clfrBob.code.length != 0);
        assertApproxEqAbs(bob.balance, 32.90 ether, 10**5);
        assert(operatorOne.balance == 0);
        assertApproxEqAbs(address(treasury).balance, 0.08 ether, 10**5);
        assertApproxEqAbs(feeRecipientOne.balance, 0.02 ether, 10**5);
    }

    function testWithdrawCLFeesExitedValidator_RewardsAfterRequest() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(address(treasury).balance == 0 ether);
        assert(feeRecipientOne.balance == 0);
        vm.deal(address(clfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.requestValidatorsExit(publicKey);
        vm.deal(address(clfrBob), 34 ether); // skimming + exit + rewards earned since last skimming
        vm.prank(bob);
        stakingContract.withdrawCLFee(publicKey);
        assert(clfrBob.code.length != 0);
        assertApproxEqAbs(bob.balance, 33.80 ether, 10**5);
        assert(operatorOne.balance == 0);
        assertApproxEqAbs(address(treasury).balance, 0.16 ether, 10**5);
        assertApproxEqAbs(feeRecipientOne.balance, 0.04 ether, 10**5);
    }

    function testWithdrawCLFeesExitedValidator_UserTriesToStealFee() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(address(treasury).balance == 0 ether);
        assert(feeRecipientOne.balance == 0);
        vm.prank(bob);
        stakingContract.requestValidatorsExit(publicKey);
        vm.deal(address(clfrBob), 2 ether); // skimming happens between request & actual exit
        vm.deal(address(clfrBob), 32 ether); // withdrawer send 30 ETH to the fee recipient, using a self destructing contract
        vm.prank(bob);
        stakingContract.withdrawCLFee(publicKey);
        assertEq(bob.balance, 32 ether); // no fee was paid on the last withdraw, it was treated as an exiting validator
        vm.deal(address(clfrBob), 32 ether);
        vm.prank(bob);
        stakingContract.withdrawCLFee(publicKey); // The user tried to scam the commission, as a consequence the fee is applied to their principal
        assert(clfrBob.code.length != 0);
        assertEq(bob.balance, 60.8 ether);
        assert(operatorOne.balance == 0);
        assertEq(address(treasury).balance, 2.56 ether);
        assertEq(feeRecipientOne.balance, 0.64 ether);
    }

    function testWithdrawCLFeesEditedOperatorFee() public {
        vm.startPrank(admin);
        stakingContract.setOperatorFee(5000);
        vm.stopPrank();
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);
        assert(address(treasury).balance == 0);
        vm.deal(address(clfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.requestValidatorsExit(publicKey);
        vm.deal(address(clfrBob), 33 ether);
        vm.prank(bob);
        stakingContract.withdrawCLFee(publicKey);
        assert(clfrBob.code.length != 0);

        assertApproxEqAbs(bob.balance, 32.90 ether, 10**5);
        assert(operatorOne.balance == 0);
        assertApproxEqAbs(address(treasury).balance, 0.05 ether, 10**5);
        assertApproxEqAbs(feeRecipientOne.balance, 0.05 ether, 10**5);
    }

    function testWithdrawCLFeesSkimmedValidator() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);
        assert(address(treasury).balance == 0);
        vm.deal(address(clfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.withdrawCLFee(publicKey);
        assert(clfrBob.code.length != 0);
        assertApproxEqAbs(bob.balance, 0.90 ether, 10**5);
        assert(operatorOne.balance == 0);
        assertApproxEqAbs(address(treasury).balance, 0.08 ether, 10**5);
        assertApproxEqAbs(feeRecipientOne.balance, 0.02 ether, 10**5);
    }

    function testWithdrawCLFeesSkimmedValidator_asAdmin() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);
        assert(address(treasury).balance == 0);
        vm.deal(address(clfrBob), 1 ether);
        vm.prank(admin);
        stakingContract.withdrawCLFee(publicKey);
        assert(clfrBob.code.length != 0);
        assertApproxEqAbs(bob.balance, 0.90 ether, 10**5);
        assert(operatorOne.balance == 0);
        assertApproxEqAbs(address(treasury).balance, 0.08 ether, 10**5);
        assertApproxEqAbs(feeRecipientOne.balance, 0.02 ether, 10**5);
    }

    function testWithdrawCLFeesSkimmedValidator_asRandom() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);
        assert(address(treasury).balance == 0);
        vm.deal(address(clfrBob), 1 ether);
        vm.expectRevert(abi.encodeWithSignature("InvalidWithdrawer()"));
        vm.prank(address(0xdede));
        stakingContract.withdrawCLFee(publicKey);
    }

    function testBatchWithdrawCLFees_asAdmin() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        bytes
            memory publicKey2 = hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060";
        vm.deal(bob, 64 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey2) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        address clfrBob2 = stakingContract.getCLFeeRecipient(publicKey2);
        bytes memory publicKeys = BytesLib.concat(publicKey, publicKey2);
        vm.deal(address(clfrBob), 1 ether);
        vm.deal(address(clfrBob2), 1 ether);
        vm.prank(admin);
        stakingContract.batchWithdrawCLFee(publicKeys);
        assertApproxEqAbs(bob.balance, 1.8 ether, 10**6);
        assert(operatorOne.balance == 0);
        assertApproxEqAbs(address(treasury).balance, 0.16 ether, 10**5);
        assertApproxEqAbs(feeRecipientOne.balance, 0.04 ether, 10**5);
    }

    function testBatchWithdrawCLFees_WrongSecondWithdrawer() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        bytes
            memory publicKey2 = hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060";
        vm.deal(bob, 32 ether);
        address bob2 = makeAddr("bob2");
        vm.deal(bob2, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        vm.prank(bob2);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey2) == bob2);
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        address clfrBob2 = stakingContract.getCLFeeRecipient(publicKey2);
        bytes memory publicKeys = BytesLib.concat(publicKey, publicKey2);
        vm.deal(address(clfrBob), 1 ether);
        vm.deal(address(clfrBob2), 1 ether);
        vm.expectRevert(abi.encodeWithSignature("InvalidWithdrawer()"));
        vm.prank(bob);
        stakingContract.batchWithdrawCLFee(publicKeys);
    }

    function testBatchWithdrawCLFees() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        bytes
            memory publicKey2 = hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060";
        vm.deal(bob, 64 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey2) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        address clfrBob2 = stakingContract.getCLFeeRecipient(publicKey2);
        bytes memory publicKeys = BytesLib.concat(publicKey, publicKey2);
        vm.deal(address(clfrBob), 1 ether);
        vm.deal(address(clfrBob2), 1 ether);
        vm.prank(bob);
        stakingContract.batchWithdrawCLFee(publicKeys);
        assertApproxEqAbs(bob.balance, 1.8 ether, 10**6);
        assert(operatorOne.balance == 0);
        assertApproxEqAbs(address(treasury).balance, 0.16 ether, 10**5);
        assertApproxEqAbs(feeRecipientOne.balance, 0.04 ether, 10**5);
    }

    function testBatchWithdrawCLFees_WrongPublicKeys() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        bytes
            memory publicKey2 = hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060";
        vm.deal(bob, 64 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey2) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        address clfrBob2 = stakingContract.getCLFeeRecipient(publicKey2);
        bytes memory publicKeys = BytesLib.concat(publicKey, publicKey2);
        publicKeys = BytesLib.concat(publicKeys, hex"66");
        vm.deal(address(clfrBob), 1 ether);
        vm.deal(address(clfrBob2), 1 ether);
        vm.expectRevert(abi.encodeWithSignature("InvalidPublicKeys()"));
        vm.prank(bob);
        stakingContract.batchWithdrawCLFee(publicKeys);
    }

    function testWithdrawCLFeesSlashedValidator() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        // Validator accumulated ~1 ETH or rewards then get slashed for 1 ETH + exit drain
        // Less than 32 ETH land on the fee recipient
        vm.deal(address(clfrBob), 31.95 ether);
        vm.prank(bob);
        stakingContract.withdrawCLFee(publicKey);

        // In this case the user will the be manually rebated and covered by insurance
        assert(clfrBob.code.length != 0);
        assertApproxEqAbs(bob.balance, 28.755 ether, 10**6);
        assertEq(operatorOne.balance, 0);
    }

    function testWithdrawCLFeesSlashedValidatorWithRewards() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        vm.deal(address(clfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.requestValidatorsExit(publicKey);
        vm.deal(address(clfrBob), 28.755 ether);
        vm.prank(bob);
        stakingContract.withdrawCLFee(publicKey);

        // In this case the user will the be manually rebated and covered by insurance
        assert(clfrBob.code.length != 0);
        assertApproxEqAbs(bob.balance, 25.8795 ether, 10**6);
        assertEq(operatorOne.balance, 0);
    }

    function testWithdrawCLFeesAlreadyDeployed() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);
        vm.deal(address(clfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.withdrawCLFee(publicKey);
        assert(clfrBob.code.length != 0);
        assertApproxEqAbs(bob.balance, 0.90 ether, 10**5);
        assert(operatorOne.balance == 0);
        assertApproxEqAbs(address(treasury).balance, 0.08 ether, 10**5);
        assertApproxEqAbs(feeRecipientOne.balance, 0.02 ether, 10**5);

        vm.deal(address(clfrBob), 1 ether);
        vm.prank(bob);
        stakingContract.requestValidatorsExit(publicKey);
        vm.deal(address(clfrBob), 33 ether);
        vm.prank(bob);
        stakingContract.withdrawCLFee(publicKey);

        assertApproxEqAbs(bob.balance, 33.80 ether, 10**6);
        assert(operatorOne.balance == 0);
        assertApproxEqAbs(address(treasury).balance, 0.16 ether, 10**5);
        assertApproxEqAbs(feeRecipientOne.balance, 0.04 ether, 10**5);
    }

    function testWithdrawCLFeesEmptyWithdrawal() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.expectRevert(abi.encodeWithSignature("ZeroBalanceWithdrawal()"));
        stakingContract.withdrawCLFee(publicKey);
        vm.stopPrank();
        assertEq(bob.balance, 0);
        assertEq(address(treasury).balance, 0);
        assertEq(feeRecipientOne.balance, 0);
    }

    function testWithdrawAllFees() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();

        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);

        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);
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

        assertApproxEqAbs(bob.balance, 33.80 ether, 10**5);
        assert(operatorOne.balance == 0);
        assertApproxEqAbs(address(treasury).balance, 0.16 ether, 10**5);
        assertApproxEqAbs(feeRecipientOne.balance, 0.04 ether, 10**5);
    }

    function testWithdrawAllFees_asAdmin() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();

        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        vm.deal(address(clfrBob), 1 ether);

        address elfrBob = stakingContract.getELFeeRecipient(publicKey);
        assert(elfrBob.code.length == 0);
        vm.deal(address(elfrBob), 1 ether);

        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);
        assert(address(treasury).balance == 0);

        vm.prank(admin);
        stakingContract.withdraw(publicKey);

        assertApproxEqAbs(bob.balance, 1.80 ether, 10**5);
        assert(operatorOne.balance == 0);
        assertApproxEqAbs(address(treasury).balance, 0.16 ether, 10**5);
        assertApproxEqAbs(feeRecipientOne.balance, 0.04 ether, 10**5);
    }

    function testWithdrawAllFees_asRandom() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();

        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        vm.deal(address(clfrBob), 33 ether);

        address elfrBob = stakingContract.getELFeeRecipient(publicKey);
        assert(elfrBob.code.length == 0);
        vm.deal(address(elfrBob), 1 ether);

        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);
        assert(address(treasury).balance == 0);

        vm.expectRevert(abi.encodeWithSignature("InvalidWithdrawer()"));
        vm.prank(address(0xdede));
        stakingContract.withdraw(publicKey);
    }

    function testBatchWithdrawAllFees() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        bytes
            memory publicKey2 = hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060";
        vm.deal(bob, 64 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey2) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(publicKey);
        address elfrBob2 = stakingContract.getELFeeRecipient(publicKey2);
        vm.deal(address(elfrBob), 1 ether);
        vm.deal(address(elfrBob2), 1 ether);
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        address clfrBob2 = stakingContract.getCLFeeRecipient(publicKey2);
        bytes memory publicKeys = BytesLib.concat(publicKey, publicKey2);
        vm.prank(bob);
        vm.deal(address(clfrBob), 1 ether);
        vm.deal(address(clfrBob2), 1 ether);
        stakingContract.batchWithdraw(publicKeys);
        assertApproxEqAbs(bob.balance, 3.6 ether, 10**6);
        assert(operatorOne.balance == 0);
        assertApproxEqAbs(address(treasury).balance, 0.32 ether, 10**5);
        assertApproxEqAbs(feeRecipientOne.balance, 0.08 ether, 10**5);
    }

    function testBatchWithdrawAllFees_asAdmin() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        bytes
            memory publicKey2 = hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060";
        vm.deal(bob, 64 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey2) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(publicKey);
        address elfrBob2 = stakingContract.getELFeeRecipient(publicKey2);
        vm.deal(address(elfrBob), 1 ether);
        vm.deal(address(elfrBob2), 1 ether);
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        address clfrBob2 = stakingContract.getCLFeeRecipient(publicKey2);
        bytes memory publicKeys = BytesLib.concat(publicKey, publicKey2);
        vm.prank(admin);
        vm.deal(address(clfrBob), 1 ether);
        vm.deal(address(clfrBob2), 1 ether);
        stakingContract.batchWithdraw(publicKeys);
        assertApproxEqAbs(bob.balance, 3.6 ether, 10**6);
        assert(operatorOne.balance == 0);
        assertApproxEqAbs(address(treasury).balance, 0.32 ether, 10**5);
        assertApproxEqAbs(feeRecipientOne.balance, 0.08 ether, 10**5);
    }

    function testBatchWithdrawAllFees_WrongWithdrawer() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        bytes
            memory publicKey2 = hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060";
        vm.deal(bob, 32 ether);
        address bob2 = makeAddr("bob2");
        vm.deal(bob2, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        vm.prank(bob2);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey2) == bob2);
        address elfrBob = stakingContract.getELFeeRecipient(publicKey);
        address elfrBob2 = stakingContract.getELFeeRecipient(publicKey2);
        vm.deal(address(elfrBob), 1 ether);
        vm.deal(address(elfrBob2), 1 ether);
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        address clfrBob2 = stakingContract.getCLFeeRecipient(publicKey2);
        bytes memory publicKeys = BytesLib.concat(publicKey, publicKey2);
        vm.prank(bob);
        vm.deal(address(clfrBob), 1 ether);
        vm.deal(address(clfrBob2), 1 ether);
        vm.expectRevert(abi.encodeWithSignature("InvalidWithdrawer()"));
        stakingContract.batchWithdraw(publicKeys);
    }

    function testBatchWithdrawAllFees_WrongPublicKeys() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        bytes
            memory publicKey2 = hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060";
        vm.deal(bob, 64 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey2) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(publicKey);
        address elfrBob2 = stakingContract.getELFeeRecipient(publicKey2);
        vm.deal(address(elfrBob), 1 ether);
        vm.deal(address(elfrBob2), 1 ether);
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        address clfrBob2 = stakingContract.getCLFeeRecipient(publicKey2);
        bytes memory publicKeys = BytesLib.concat(publicKey, publicKey2);
        publicKeys = BytesLib.concat(publicKeys, hex"66");
        vm.prank(bob);
        vm.deal(address(clfrBob), 1 ether);
        vm.deal(address(clfrBob2), 1 ether);
        vm.expectRevert(abi.encodeWithSignature("InvalidPublicKeys()"));
        stakingContract.batchWithdraw(publicKeys);
    }

    function testBatchWithdrawELFees_10() public {
        bytes
            memory publicKeys_10 = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e06014451b3fb9288549aff6dea9843b43e0c47a3b856f307732175230e254c0004e48b02414987088ac7003e148930017b49a1a8d4600f33d463c4afc07bbfc82703c9fcf81a5891f90a71c86a02faff443c6c3b2592bd44d5d3d7a93cb4aaaa105612496d61e68140a5418b468f872bf2f3e79f9cb0d9c3e889663fca02939b31e8ee3092203ee1417128e965c6406a07f68abf2ebe2689cf6c853ef126ffa8574c2a7d913e28de9147fa6b96706ea5bf9eacd1aba06edeaee155009fb912c00070774cc64136fcffde12ed731260bc5529df64da298f493561198e9d6acf42cf21e853ae7b2df85f27d2183149969d623b9237254c2cfe1d0082742eb042ac096d686dbe03c79ee31cbd03bb4682f8797043eed9f6e622814831ac5dfe1176552fb7f9b6ff38a149ae1d8414097a32fd96da6453c52fda13e3402a09e2fa6886daa4300f09c73e4bc2901b99c44744c5cfdca2994adc49ddccb195bda2510e50a4ae10de26cf96dee5e577689f51650a610a33da0a826ae47247d8d1189cb3386";
        assertEq(publicKeys_10.length, 480);
        vm.deal(bob, 320 ether);
        vm.startPrank(bob);
        for (uint256 i = 0; i < publicKeys_10.length; i += 48) {
            stakingContract.deposit{value: 32 ether}();
            assert(stakingContract.getWithdrawer(BytesLib.slice(publicKeys_10, i, 48)) == bob);
        }
        vm.stopPrank();
        for (uint256 i = 0; i < publicKeys_10.length; i += 48) {
            address elfrBob = stakingContract.getELFeeRecipient(BytesLib.slice(publicKeys_10, i, 48));
            vm.deal(address(elfrBob), 1 ether);
        }
        vm.prank(bob);
        stakingContract.batchWithdrawELFee(publicKeys_10);
        assertEq(bob.balance, 9 ether);
        assertEq(operatorOne.balance, 0);
        assertEq(feeRecipientOne.balance, 0.2 ether);
        assertEq(address(treasury).balance, 0.8 ether);
    }

    function testBatchWithdrawCLFees_10() public {
        bytes
            memory publicKeys_10 = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e06014451b3fb9288549aff6dea9843b43e0c47a3b856f307732175230e254c0004e48b02414987088ac7003e148930017b49a1a8d4600f33d463c4afc07bbfc82703c9fcf81a5891f90a71c86a02faff443c6c3b2592bd44d5d3d7a93cb4aaaa105612496d61e68140a5418b468f872bf2f3e79f9cb0d9c3e889663fca02939b31e8ee3092203ee1417128e965c6406a07f68abf2ebe2689cf6c853ef126ffa8574c2a7d913e28de9147fa6b96706ea5bf9eacd1aba06edeaee155009fb912c00070774cc64136fcffde12ed731260bc5529df64da298f493561198e9d6acf42cf21e853ae7b2df85f27d2183149969d623b9237254c2cfe1d0082742eb042ac096d686dbe03c79ee31cbd03bb4682f8797043eed9f6e622814831ac5dfe1176552fb7f9b6ff38a149ae1d8414097a32fd96da6453c52fda13e3402a09e2fa6886daa4300f09c73e4bc2901b99c44744c5cfdca2994adc49ddccb195bda2510e50a4ae10de26cf96dee5e577689f51650a610a33da0a826ae47247d8d1189cb3386";
        assertEq(publicKeys_10.length, 480);
        vm.deal(bob, 320 ether);
        vm.startPrank(bob);
        for (uint256 i = 0; i < publicKeys_10.length; i += 48) {
            stakingContract.deposit{value: 32 ether}();
            assert(stakingContract.getWithdrawer(BytesLib.slice(publicKeys_10, i, 48)) == bob);
        }
        vm.stopPrank();
        for (uint256 i = 0; i < publicKeys_10.length; i += 48) {
            address clfrBob = stakingContract.getCLFeeRecipient(BytesLib.slice(publicKeys_10, i, 48));
            vm.deal(address(clfrBob), 1 ether);
        }
        vm.prank(bob);
        stakingContract.batchWithdrawCLFee(publicKeys_10);
        assertApproxEqAbs(bob.balance, 9 ether, 10**7);
        assertEq(operatorOne.balance, 0);
        assertApproxEqAbs(address(treasury).balance, 0.8 ether, 10**6);
        assertApproxEqAbs(feeRecipientOne.balance, 0.2 ether, 10**6);
    }

    function testBatchWithdrawAllFees_10() public {
        bytes
            memory publicKeys_10 = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e06014451b3fb9288549aff6dea9843b43e0c47a3b856f307732175230e254c0004e48b02414987088ac7003e148930017b49a1a8d4600f33d463c4afc07bbfc82703c9fcf81a5891f90a71c86a02faff443c6c3b2592bd44d5d3d7a93cb4aaaa105612496d61e68140a5418b468f872bf2f3e79f9cb0d9c3e889663fca02939b31e8ee3092203ee1417128e965c6406a07f68abf2ebe2689cf6c853ef126ffa8574c2a7d913e28de9147fa6b96706ea5bf9eacd1aba06edeaee155009fb912c00070774cc64136fcffde12ed731260bc5529df64da298f493561198e9d6acf42cf21e853ae7b2df85f27d2183149969d623b9237254c2cfe1d0082742eb042ac096d686dbe03c79ee31cbd03bb4682f8797043eed9f6e622814831ac5dfe1176552fb7f9b6ff38a149ae1d8414097a32fd96da6453c52fda13e3402a09e2fa6886daa4300f09c73e4bc2901b99c44744c5cfdca2994adc49ddccb195bda2510e50a4ae10de26cf96dee5e577689f51650a610a33da0a826ae47247d8d1189cb3386";
        assertEq(publicKeys_10.length, 480);
        vm.deal(bob, 320 ether);
        vm.startPrank(bob);
        for (uint256 i = 0; i < publicKeys_10.length; i += 48) {
            stakingContract.deposit{value: 32 ether}();
            assert(stakingContract.getWithdrawer(BytesLib.slice(publicKeys_10, i, 48)) == bob);
        }
        vm.stopPrank();
        for (uint256 i = 0; i < publicKeys_10.length; i += 48) {
            address elfrBob = stakingContract.getELFeeRecipient(BytesLib.slice(publicKeys_10, i, 48));
            vm.deal(address(elfrBob), 1 ether);
            address clfrBob = stakingContract.getCLFeeRecipient(BytesLib.slice(publicKeys_10, i, 48));
            vm.deal(address(clfrBob), 1 ether);
        }
        vm.prank(bob);
        stakingContract.batchWithdraw(publicKeys_10);
        assertApproxEqAbs(bob.balance, 18 ether, 10**7);
        assertEq(operatorOne.balance, 0);
        assertApproxEqAbs(address(treasury).balance, 1.6 ether, 10**6);
        assertApproxEqAbs(feeRecipientOne.balance, 0.4 ether, 10**6);
    }

    function testRequestValidatorsExits_OneValidator() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        vm.expectEmit(true, true, true, true);
        emit ExitRequest(bob, publicKey);
        vm.prank(bob);
        stakingContract.requestValidatorsExit(publicKey);
    }

    function testRequestValidatorsExits_TwoValidators() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        bytes
            memory publicKey2 = hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey2) == bob);
        vm.stopPrank();

        bytes memory publicKeys = BytesLib.concat(publicKey, publicKey2);

        vm.expectEmit(true, true, true, true);
        emit ExitRequest(bob, publicKey);
        vm.expectEmit(true, true, true, true);
        emit ExitRequest(bob, publicKey2);
        vm.prank(bob);
        stakingContract.requestValidatorsExit(publicKeys);
    }

    function testRequestValidatorsExits_WrongWithdrawer() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        vm.prank(address(1337));
        stakingContract.requestValidatorsExit(publicKey);
    }

    function testRequestValidatorsExits_WrongPublicKeys() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        vm.expectRevert(abi.encodeWithSignature("InvalidPublicKeys()"));
        vm.prank(bob);
        bytes
            memory corruptedPublicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd43607";
        stakingContract.requestValidatorsExit(corruptedPublicKey);
    }

    function testRequestValidatorsExits_WrongSecondWithdrawer() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        bytes
            memory publicKey2 = hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060";
        vm.deal(bob, 32 ether);
        vm.deal(alice, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        vm.startPrank(alice);
        stakingContract.deposit{value: 32 ether}();
        assert(stakingContract.getWithdrawer(publicKey2) == alice);
        vm.stopPrank();

        bytes memory publicKeys = BytesLib.concat(publicKey, publicKey2);

        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        vm.prank(bob);
        stakingContract.requestValidatorsExit(publicKeys);
    }
}
