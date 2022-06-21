//SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.10;

import "solmate/test/utils/DSTestPlus.sol";
import "forge-std/Vm.sol";
import "../contracts/StakingContract.sol";
import "../contracts/interfaces/IDepositContract.sol";
import "../contracts/ExecutionLayerFeeRecipient.sol";
import "../contracts/ConsensusLayerFeeRecipient.sol";
import "./UserFactory.sol";
import "../contracts/libs/BytesLib.sol";

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
    ExecutionLayerFeeRecipient internal elfr;
    ConsensusLayerFeeRecipient internal clfr;
    UserFactory internal uf;

    address internal admin = address(1);
    address internal bob = address(2);
    address internal alice = address(3);
    address internal operatorOne = address(4);
    address internal feeRecipientOne = address(44);
    address internal operatorTwo = address(5);
    address internal feeRecipientTwo = address(55);

    bytes32 salt = bytes32(0);

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
        elfr = new ExecutionLayerFeeRecipient(1);
        clfr = new ConsensusLayerFeeRecipient(1);
        stakingContract = new StakingContract();
        depositContract = new DepositContractMock();
        stakingContract.initialize_1(admin, address(depositContract), address(elfr), address(clfr), 500, 500);

        vm.startPrank(admin);
        stakingContract.addOperator(operatorOne, feeRecipientOne);
        stakingContract.addOperator(operatorTwo, feeRecipientTwo);
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
            bytes
                memory publicKeys = hex"24046f7be8644e2b872363d5a4d58836deeb2deab6996a7e57f8c7583872786d1b81e378c4188ec3094236a31e31bd83c89e108b2d2e26e9dba2cc7a4f898c5f4b62d43f8e76c7cf64d02aab46afc436d7759d2b2e4d4aca97687b0022bec98307d1b050eafad3ba0fdf22cf645936ebd9e3c1ae913badc7307e02c38d778b10259b571237cc826a030b44a4fd53da790a84e6578890a7c801bbc2212bfccfecf88da5203e96c29b404fd9a61400f808e11a10fe39c9d97de43ad20867b3f5a71cc86d46d1058ab033c63c2369774cabe009231a85836abe39f9f5b41158a2505305d6e500cd64eb8e479e59c72945b9aaa177fd4a99d36dac27400609e098b8ce8638dc0ae641043107e47ccc495bdf7f40811e1c67103605241ea329ebd34e85d3184f79fe2b4642007709c2f4912853d72e0399930a62c915e50d4e1a1bd0fa26f021f37f519b86e168a181604c9c4b9af621932f09601bd9d5d0a9ee349076765d1baea4eef0fc16d4ebc861569ec37857c1d654ca442d2b0c85e97c5d56289a42afa5040cb1901bd03faf7011780599ed2cf826b8a2dd9deece7d9ecd7d7be2751bb42645f0253732447092311597a0f7672268125a95464c541e7fb1e3e08151f038adec85a60db0a9a9430ca80ffdbabe557aa2e0f69e6aed98527c91";
            bytes
                memory signatures = hex"57412124b1730be9e30a395b5e7af34e7cecd16b8cc3a5b255f7b5e5cd92a3aa328401d07268d0ffaed8867d8a6288e569c547506b3f124f45f37d17bf0ec9c55917db458ba9cf8d498b0572b253435991f57f4e496763bbbbc3d92bd50c7f05304112ec1a45d0a8e5b3aa309dc4377ee8beb9d79b08f6bd60d0696b29acff9539cb836f2f00bbf888cfd28e4cfa4f317d6c3babdc0e121247789137eae3553de0c67ccbe2a5135f8f70dc5a79023544da8d608c825ef06ec32d315b4b026dd8f7f667af7368efead94f6f38418b1527a7c4500424410b8b09c580e89bc8cfba27eed8cea56311b9446313de80bb24f09072ee0ef5ceb504d7bdefed1e3fa5a8aee876b44302f7ff1b8a039033c3ed370a7b02a0cc23a5b7b4d7499649e6ee3f37d51fcbde910f6d10c1512eaf8924a8c7f150d280efb293e719ff07357c01482b1b6cc75a3d0118bdc058cccf67fbcbaad1423f2940d0191bb1d8257a2d827e74a3963ccbd316081105be05e8471d8fa466b4935c0dce7cb6bcb36dd1ef2a156841be9793a00a3aefb8e55ef91f6f17ba49cb9025dc441fd381ad5194de34d9032df1f26930537f0fcd509638403c3ce8df19f2106904cfd82e92627283fdc8ac5165848dabbf1b1566302ddeb72f70a17bb1520b8cc3b41c007e3bf334af34e900ef5fc0b3fb8642f7bd0b109c7cfd204c7e0039c10d1592ec02e8af9ea9653df70fed29d30c2784e3ff187caabb0a588db0fd2bb77565909cd5f5895a56d32510fb90735d5f1ca1dd4b9bbf7ce3e8d3745a879093e90d883875b865a69d7b79b2bf4cf42cedf084447c95e31d11c41adff8a9939550c87996d7f4002c9064bb2e6e675310caf556a7e44f07e92704c7589c2e335cbd4dc3fde2bfd7d79ad050bee3066e5aed5e97c445e0c54c9f5c5febbc5182aeaad91acc0e9b58bfed9049a2ccc09bf4b2534220f24c8c387306a498fffe66d3cd50c34296fb456fe2656999893ed1ac5ed8eb1845455412833e9abec7274714ccbef2c20172df5fdde1e1bb142c5987c8aec208fb11b383cf4b1c3851d8ef27561176605487b5c83923fa731e94ee6ec59fe8307df91c2552a1e318933f32c9b2f27896f932c69b9dc0c8860e78663a5be9480be01b19bc9f56b955e442af493f0d267d4ed8e466eaa345af4e476beade96d6460a4e701c1604f190eafc6c42ed751943cb7393b7bb871c9849f056bddf731fb1eed5b8f030330d245834834994f49d1ecb6eac952e02baa1298f482b622caaa4b6479afd6729cfc2c14ab571e4d32973016cded551becd595af5bcb1cf53db1b55ca1b580da6564f065ac8c8c1709ccdc30003125d54";

            vm.startPrank(operatorTwo);
            stakingContract.addValidators(1, 10, publicKeys, signatures);
            vm.stopPrank();
        }

        {
            vm.startPrank(admin);
            stakingContract.setOperatorLimit(0, 10);
            stakingContract.setOperatorLimit(1, 10);
            vm.stopPrank();
        }
    }

    function testGetAdmin() public {
        assertEq(stakingContract.getAdmin(), admin);
    }

    function testSetAdmin(uint256 _adminSalt) public {
        address newAdmin = uf._new(_adminSalt);
        assertEq(stakingContract.getAdmin(), admin);
        vm.startPrank(admin);
        stakingContract.setAdmin(newAdmin);
        vm.stopPrank();
        assertEq(stakingContract.getAdmin(), newAdmin);
    }

    function testReinitialization() public {
        vm.expectRevert(abi.encodeWithSignature("AlreadyInitialized()"));
        stakingContract.initialize_1(admin, address(depositContract), address(0), address(0), 500, 500);
    }

    function testSetAdminUnauthorized(uint256 _adminSalt) public {
        address newAdmin = uf._new(_adminSalt);
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        stakingContract.setAdmin(newAdmin);
    }

    function testGetOperator() public {
        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool banned
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 0);
        assertEq(available, 10);
        assert(banned == false);

        (operatorAddress, feeRecipientAddress, limit, keys, funded, available, banned) = stakingContract.getOperator(1);
        assertEq(operatorAddress, operatorTwo);
        assertEq(feeRecipientAddress, feeRecipientTwo);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 0);
        assertEq(available, 10);
        assert(banned == false);
    }

    function testAddOperator(uint256 _operatorSalt) public {
        address newOperator = uf._new(_operatorSalt);
        address newOperatorFeeRecipient = uf._new(_operatorSalt);

        uint256 operatorIndex;

        vm.startPrank(admin);
        operatorIndex = stakingContract.addOperator(newOperator, newOperatorFeeRecipient);
        vm.stopPrank();

        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool banned
        ) = stakingContract.getOperator(operatorIndex);
        assertEq(operatorAddress, newOperator);
        assertEq(feeRecipientAddress, newOperatorFeeRecipient);
        assertEq(limit, 0);
        assertEq(keys, 0);
        assertEq(funded, 0);
        assertEq(available, 0);
        assert(banned == false);
    }

    function testAddOperatorUnauthorized(uint256 _operatorSalt) public {
        address newOperator = uf._new(_operatorSalt);
        address newOperatorFeeRecipient = uf._new(_operatorSalt);

        uint256 operatorIndex;

        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        operatorIndex = stakingContract.addOperator(newOperator, newOperatorFeeRecipient);
    }

    function testSetOperatorAddresses(uint256 _operatorSalt) public {
        address newOperator = uf._new(_operatorSalt);
        address newOperatorFeeRecipient = uf._new(_operatorSalt);

        uint256 operatorIndex;

        // Registers an operator
        vm.startPrank(admin);
        operatorIndex = stakingContract.addOperator(newOperator, newOperatorFeeRecipient);
        vm.stopPrank();

        address updatedOperator = uf._new(_operatorSalt);

        // Try to update the operator address
        vm.startPrank(newOperatorFeeRecipient);
        stakingContract.setOperatorAddresses(operatorIndex, updatedOperator, newOperatorFeeRecipient);
        vm.stopPrank();

        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool banned
        ) = stakingContract.getOperator(operatorIndex);
        assertEq(operatorAddress, updatedOperator);
        assertEq(feeRecipientAddress, newOperatorFeeRecipient);
        assertEq(limit, 0);
        assertEq(keys, 0);
        assertEq(funded, 0);
        assertEq(available, 0);
        assert(banned == false);
    }

    function testSetOperatorAddressesUnauthorized(uint256 _operatorSalt) public {
        address newOperator = uf._new(_operatorSalt);
        address newOperatorFeeRecipient = uf._new(_operatorSalt);
        address wrongOperatorFeeRecipient = uf._new(_operatorSalt);

        uint256 operatorIndex;

        // Register the operator to try an update right after
        vm.startPrank(admin);
        operatorIndex = stakingContract.addOperator(newOperator, newOperatorFeeRecipient);
        vm.stopPrank();

        // Try to update the operator addresses
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        stakingContract.setOperatorAddresses(operatorIndex, newOperator, wrongOperatorFeeRecipient);
    }

    function testSetOperatorLimit(uint256 _operatorSalt, uint8 _limit) public {
        address newOperator = uf._new(_operatorSalt);
        address newOperatorFeeRecipient = uf._new(_operatorSalt);

        uint256 operatorIndex;

        vm.startPrank(admin);
        operatorIndex = stakingContract.addOperator(newOperator, newOperatorFeeRecipient);
        vm.stopPrank();

        (, , uint256 limit, , , , ) = stakingContract.getOperator(operatorIndex);
        assertEq(limit, 0);

        if (_limit > 0) {
            vm.startPrank(newOperator);
            stakingContract.addValidators(
                operatorIndex,
                _limit,
                genBytes(48 * uint256(_limit)),
                genBytes(96 * uint256(_limit))
            );
            vm.stopPrank();
        }

        vm.startPrank(admin);
        stakingContract.setOperatorLimit(operatorIndex, _limit);
        vm.stopPrank();

        (, , limit, , , , ) = stakingContract.getOperator(operatorIndex);
        assertEq(limit, _limit);
    }

    function testSetOperatorLimitUnauthorized() public {
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        stakingContract.setOperatorLimit(0, 10);
    }

    function testSetOperatorLimitTooHighUnauthorized() public {
        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSignature("OperatorLimitTooHigh(uint256,uint256)", 11, 10));
        stakingContract.setOperatorLimit(0, 11);
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
            bool banned
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 0);
        assertEq(available, 10);
        assert(banned == false);

        vm.startPrank(operatorOne);
        stakingContract.addValidators(0, 10, publicKeys, signatures);
        vm.stopPrank();

        (operatorAddress, feeRecipientAddress, limit, keys, funded, available, banned) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 20);
        assertEq(funded, 0);
        assertEq(available, 10);
        assert(banned == false);

        vm.startPrank(admin);
        stakingContract.setOperatorLimit(0, 20);
        vm.stopPrank();

        (operatorAddress, feeRecipientAddress, limit, keys, funded, available, banned) = stakingContract.getOperator(0);

        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 20);
        assertEq(keys, 20);
        assertEq(funded, 0);
        assertEq(available, 20);
        assert(banned == false);
    }

    function testAddValidatorsBannedOperatorOne() public {
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
            bool banned
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipient, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 0);
        assertEq(available, 10);
        assert(banned == false);

        vm.startPrank(admin);
        stakingContract.banOperator(0, address(1));
        vm.stopPrank();

        (operatorAddress, feeRecipient, limit, keys, funded, available, banned) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipient, address(1));
        assertEq(limit, 0);
        assertEq(keys, 10);
        assertEq(funded, 0);
        assertEq(available, 0);
        assert(banned == true);

        vm.startPrank(operatorOne);
        vm.expectRevert(abi.encodeWithSignature("Banned()"));
        stakingContract.addValidators(0, 10, publicKeys, signatures);
        vm.stopPrank();

        vm.startPrank(operatorOne);
        uint256[] memory indexes = new uint256[](1);
        indexes[0] = 0;
        vm.expectRevert(abi.encodeWithSignature("Banned()"));
        stakingContract.removeValidators(0, indexes);
        vm.stopPrank();

        vm.startPrank(admin);
        stakingContract.unbanOperator(0, feeRecipientOne);
        vm.stopPrank();

        vm.startPrank(operatorOne);
        stakingContract.addValidators(0, 10, publicKeys, signatures);
        vm.stopPrank();

        (operatorAddress, feeRecipient, limit, keys, funded, available, banned) = stakingContract.getOperator(0);

        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipient, feeRecipientOne);
        assertEq(limit, 0);
        assertEq(keys, 20);
        assertEq(funded, 0);
        assertEq(available, 0);
        assert(banned == false);
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
            bool banned
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 0);
        assertEq(available, 10);
        assert(banned == false);

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
            bool banned
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 0);
        assertEq(available, 10);
        assert(banned == false);

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
        stakingContract.removeValidators(0, indexes);
        vm.stopPrank();

        (operatorAddress, feeRecipientAddress, limit, keys, funded, available, banned) = stakingContract.getOperator(0);

        assertEq(operatorAddress, operatorOne);
        assertEq(limit, 0);
        assertEq(keys, 0);
        assertEq(funded, 0);
        assertEq(available, 0);
        assert(banned == false);
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
        vm.deal(user, 32 * 3 ether);

        vm.startPrank(user);
        (bool _success, ) = address(stakingContract).call{value: 32 * 3 ether}("");
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

        vm.startPrank(operatorTwo);
        stakingContract.removeValidators(1, indexes);
        vm.stopPrank();

        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool banned
        ) = stakingContract.getOperator(1);
        assertEq(operatorAddress, operatorTwo);
        assertEq(feeRecipientAddress, feeRecipientTwo);
        assertEq(limit, 1);
        assertEq(keys, 1);
        assertEq(funded, 1);
        assertEq(available, 0);
        assert(banned == false);
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
            memory pk = hex"24046f7be8644e2b872363d5a4d58836deeb2deab6996a7e57f8c7583872786d1b81e378c4188ec3094236a31e31bd83";

        assertEq(stakingContract.getWithdrawer(pk), user);

        vm.startPrank(user);
        stakingContract.setWithdrawer(pk, anotherUser);
        vm.stopPrank();

        assertEq(stakingContract.getWithdrawer(pk), anotherUser);
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

        bytes
            memory pk = hex"24046f7be8644e2b872363d5a4d58836deeb2deab6996a7e57f8c7583872786d1b81e378c4188ec3094236a31e31bd83";

        assertEq(stakingContract.getWithdrawer(pk), user);

        vm.startPrank(anotherUser);
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        stakingContract.setWithdrawer(pk, anotherUser);
        vm.stopPrank();
    }
}

contract StakingContractThreeValidatorsTest is DSTestPlus {
    Vm internal vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    StakingContract internal stakingContract;
    DepositContractMock internal depositContract;
    UserFactory internal uf;

    address internal admin = address(1);
    address internal bob = address(2);
    address internal alice = address(3);
    address internal operatorOne = address(4);
    address internal feeRecipientOne = address(44);

    address internal operatorTwo = address(5);
    address internal feeRecipientTwo = address(55);

    address internal operatorThree = address(5);
    address internal feeRecipientThree = address(55);

    function setUp() public {
        uf = new UserFactory();
        stakingContract = new StakingContract();
        depositContract = new DepositContractMock();
        stakingContract.initialize_1(admin, address(depositContract), address(0), address(0), 500, 500);

        vm.startPrank(admin);
        stakingContract.addOperator(operatorOne, feeRecipientOne);
        stakingContract.addOperator(operatorTwo, feeRecipientTwo);
        stakingContract.addOperator(operatorThree, feeRecipientThree);
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
            bytes
                memory publicKeys = hex"24046f7be8644e2b872363d5a4d58836deeb2deab6996a7e57f8c7583872786d1b81e378c4188ec3094236a31e31bd83c89e108b2d2e26e9dba2cc7a4f898c5f4b62d43f8e76c7cf64d02aab46afc436d7759d2b2e4d4aca97687b0022bec98307d1b050eafad3ba0fdf22cf645936ebd9e3c1ae913badc7307e02c38d778b10259b571237cc826a030b44a4fd53da790a84e6578890a7c801bbc2212bfccfecf88da5203e96c29b404fd9a61400f808e11a10fe39c9d97de43ad20867b3f5a71cc86d46d1058ab033c63c2369774cabe009231a85836abe39f9f5b41158a2505305d6e500cd64eb8e479e59c72945b9aaa177fd4a99d36dac27400609e098b8ce8638dc0ae641043107e47ccc495bdf7f40811e1c67103605241ea329ebd34e85d3184f79fe2b4642007709c2f4912853d72e0399930a62c915e50d4e1a1bd0fa26f021f37f519b86e168a181604c9c4b9af621932f09601bd9d5d0a9ee349076765d1baea4eef0fc16d4ebc861569ec37857c1d654ca442d2b0c85e97c5d56289a42afa5040cb1901bd03faf7011780599ed2cf826b8a2dd9deece7d9ecd7d7be2751bb42645f0253732447092311597a0f7672268125a95464c541e7fb1e3e08151f038adec85a60db0a9a9430ca80ffdbabe557aa2e0f69e6aed98527c91";
            bytes
                memory signatures = hex"57412124b1730be9e30a395b5e7af34e7cecd16b8cc3a5b255f7b5e5cd92a3aa328401d07268d0ffaed8867d8a6288e569c547506b3f124f45f37d17bf0ec9c55917db458ba9cf8d498b0572b253435991f57f4e496763bbbbc3d92bd50c7f05304112ec1a45d0a8e5b3aa309dc4377ee8beb9d79b08f6bd60d0696b29acff9539cb836f2f00bbf888cfd28e4cfa4f317d6c3babdc0e121247789137eae3553de0c67ccbe2a5135f8f70dc5a79023544da8d608c825ef06ec32d315b4b026dd8f7f667af7368efead94f6f38418b1527a7c4500424410b8b09c580e89bc8cfba27eed8cea56311b9446313de80bb24f09072ee0ef5ceb504d7bdefed1e3fa5a8aee876b44302f7ff1b8a039033c3ed370a7b02a0cc23a5b7b4d7499649e6ee3f37d51fcbde910f6d10c1512eaf8924a8c7f150d280efb293e719ff07357c01482b1b6cc75a3d0118bdc058cccf67fbcbaad1423f2940d0191bb1d8257a2d827e74a3963ccbd316081105be05e8471d8fa466b4935c0dce7cb6bcb36dd1ef2a156841be9793a00a3aefb8e55ef91f6f17ba49cb9025dc441fd381ad5194de34d9032df1f26930537f0fcd509638403c3ce8df19f2106904cfd82e92627283fdc8ac5165848dabbf1b1566302ddeb72f70a17bb1520b8cc3b41c007e3bf334af34e900ef5fc0b3fb8642f7bd0b109c7cfd204c7e0039c10d1592ec02e8af9ea9653df70fed29d30c2784e3ff187caabb0a588db0fd2bb77565909cd5f5895a56d32510fb90735d5f1ca1dd4b9bbf7ce3e8d3745a879093e90d883875b865a69d7b79b2bf4cf42cedf084447c95e31d11c41adff8a9939550c87996d7f4002c9064bb2e6e675310caf556a7e44f07e92704c7589c2e335cbd4dc3fde2bfd7d79ad050bee3066e5aed5e97c445e0c54c9f5c5febbc5182aeaad91acc0e9b58bfed9049a2ccc09bf4b2534220f24c8c387306a498fffe66d3cd50c34296fb456fe2656999893ed1ac5ed8eb1845455412833e9abec7274714ccbef2c20172df5fdde1e1bb142c5987c8aec208fb11b383cf4b1c3851d8ef27561176605487b5c83923fa731e94ee6ec59fe8307df91c2552a1e318933f32c9b2f27896f932c69b9dc0c8860e78663a5be9480be01b19bc9f56b955e442af493f0d267d4ed8e466eaa345af4e476beade96d6460a4e701c1604f190eafc6c42ed751943cb7393b7bb871c9849f056bddf731fb1eed5b8f030330d245834834994f49d1ecb6eac952e02baa1298f482b622caaa4b6479afd6729cfc2c14ab571e4d32973016cded551becd595af5bcb1cf53db1b55ca1b580da6564f065ac8c8c1709ccdc30003125d54";

            vm.startPrank(operatorTwo);
            stakingContract.addValidators(1, 10, publicKeys, signatures);
            vm.stopPrank();
        }

        {
            bytes
                memory publicKeys = hex"9513f9219894d2daca9cfee1179107fee1ba7bd3ecba34bf0307d206797d2289e93494c41c083fb0dcf755981957dbf4eef0d296ace474a8855e6a7868c804350c8f4513ce184bdcb91098af5cce79c3af6700fdc4fb5d12c7f118615372f35b01e9c5cf390e68d2830258b008fbe6a0d9c3f6873d15d08699702246428d9c6c0a39af18f14b0264a7619d902b8e515d49b2266f5eb393853bd1d44b2cde121ef385c60112803cc6642f5728f27e6ab46f74837ed5007ff43225217c3addb664012c02d12be4431885fb93a49d416d8a6ee912c01991ea90176f65a9d1f29d163c8b73b6a576f6b88f7c5172800d7fe45f425cf7f9a45dc575015d613b91816203ccd534e877ba65b3734ef5abe02e11e75fc3c7513f233997370317fbe2eb27e0cba3ffbd488f9da412b12926e20ded36d79ae5eeed81279e89dae9003d64e2f70b169fafd291674e6a0b4ff3c092a4bc06b05a6a6aac393a1f27390bc8cc3cd5dcd489706aa0fb2d0f432d5eac172ea97887d94ff90d011cf091f07888726e0de8d1295b3a1fafa25cd4b45a644c1b55043dd3cfefb79502642e7c3d57998416829729bc3dc00d8f8b45a0f0a2e2a91c388030557eaaf95ced94fe4a416295a7d15b1917c1b152d5dcbe92f50ff06c2973c3bc1245f2b6eb4e1506d4b428a3";
            bytes
                memory signatures = hex"26a2d42cda4543a2b3f070966ccc51efe5427bc633150ea6ae2d87724d7a60c18d3a10d4291aa29a338b51ee4f29bbfd9905aaaad3325a24b36a7c18fc9923ec877879c18d4f96300aa47cb81a009218b1e4c6851581a0d7ed01490b94522563726b0e7ab6261e077468ff8faec162c13836a0f94ddf2659be04688fa085b70a9d2667b80d25fd11b0eb3b67e56a300a6a01578457d55d2e6f4f1fc82bee3c9168d488cfcb437453f55e9481ce5920bed8ad176f466f95ceb3c8779d3240889266ac73078992260ee340ac971c8c57dcdda6a944103beae2d499119b9d78d8c5e679ad67669d8cba29396ae18d7162715c79d8514db18e97860017553c7205fcfc70ab165f3c956dc9c8f20b5975db4f6d4b615776fbaf64367e1dd68a29a6d09123a07becfbead75d132250d4c396b34212ad9eebce7e7bc02b63cb4deaed700cad0a0b521db258e019db921c1f81b619f4848fb9ab9f87e4029f673d21cf9fad9c3ea548763552880b962c7767af192ff7aaada11b76bc2e1b1dd1c9d849884c616037ec265e5aee843e8cc718ceb60f7f1d92829db0fd9ac0bee42025bd5fe1f3f7584e6f1b27fe837bc2559a61b2dbae6188c903d4a4435c1d8562d79da202b3ff9e625112442ae86dc709a3a9662ac3e53f8e001f62133bbb42091f0649af49ad28999990707178e87a6dde37d2a577a3c8db46866dd3c4977e290f367454effa0f10dd609ea929738eaf7a9068fd802378230f844358432dcd6995f0857c12ccb076b40d64f7edfbf5b5805878a13445b8cf99d4a66ced66d0029fde05507c75d14d54be0ef3f710b2fbaceca5d55898319a20bd806d689c0bce461a42c5200d214202c588a7bb4a04493207210f0af210c1abc58e6fda929080541762e6657a411291d16403768c3c492a47707676a15e34e12caab1e607acdf7bb857f04bb5130a88d2e01138f196c2ab6de7da0e47bde1b05c2e1e5e6e7f23cf9196b4271179456e4e6427110e9edd2531b5ea3570b51f9c67f2563591f2eb3eef79d15656c7232a10a4d9ea47878007af6687932878b26bd2430384f5b02cf4b4be55dfa54a3f73d024f6984c39c341b22cf10783326a8421f904ae373a187c2fcd0c49d7c5b5931d5db84fca2006cce5a5eda906dd4945b55375eb65735a43455b44646256b87899a6e725a5f36a3d4d922ca44db1c883dc3cfe36a42c7b0d4b284af0cfa49e8bec7b43b4e8a01afc53af8b2059ab5f47daede24c9720e33a243d2b57707f8c7ec33fdec66f1f7fca5d82f75c6bd4d633ef877c3e271b534b7424a61d47d0c041e400c96b0e3dde1dd8e050146d2af665ff505fdcf37ad07c7130";

            vm.startPrank(operatorThree);
            stakingContract.addValidators(2, 10, publicKeys, signatures);
            vm.stopPrank();
        }

        {
            vm.startPrank(admin);
            stakingContract.setOperatorLimit(0, 10);
            stakingContract.setOperatorLimit(1, 10);
            stakingContract.setOperatorLimit(2, 10);
            vm.stopPrank();
        }
    }

    event Deposit(address indexed caller, address indexed withdrawer, bytes publicKey, bytes32 publicKeyRoot);

    function testValidatorInfoRetrieval(uint256 _userSalt, uint256 _withdrawerSalt) public {
        address user = uf._new(_userSalt);
        address withdrawer = uf._new(_withdrawerSalt);
        vm.deal(user, 32 ether);
        vm.roll(99999);
        uint256 operatorIndex = 1;

        {
            (bytes memory publicKey, bytes memory signature, address _withdrawer, bool _funded) = stakingContract
                .getValidator(operatorIndex, 0);
            assert(
                keccak256(publicKey) ==
                    keccak256(
                        hex"24046f7be8644e2b872363d5a4d58836deeb2deab6996a7e57f8c7583872786d1b81e378c4188ec3094236a31e31bd83"
                    )
            );
            assert(
                keccak256(signature) ==
                    keccak256(
                        hex"57412124b1730be9e30a395b5e7af34e7cecd16b8cc3a5b255f7b5e5cd92a3aa328401d07268d0ffaed8867d8a6288e569c547506b3f124f45f37d17bf0ec9c55917db458ba9cf8d498b0572b253435991f57f4e496763bbbbc3d92bd50c7f05"
                    )
            );
            assert(_withdrawer == address(0));
            assert(_funded == false);
        }

        vm.startPrank(user);
        stakingContract.deposit{value: 32 ether}(withdrawer);
        vm.stopPrank();

        {
            (bytes memory publicKey, bytes memory signature, address _withdrawer, bool _funded) = stakingContract
                .getValidator(operatorIndex, 0);
            assert(
                keccak256(publicKey) ==
                    keccak256(
                        hex"24046f7be8644e2b872363d5a4d58836deeb2deab6996a7e57f8c7583872786d1b81e378c4188ec3094236a31e31bd83"
                    )
            );
            assert(
                keccak256(signature) ==
                    keccak256(
                        hex"57412124b1730be9e30a395b5e7af34e7cecd16b8cc3a5b255f7b5e5cd92a3aa328401d07268d0ffaed8867d8a6288e569c547506b3f124f45f37d17bf0ec9c55917db458ba9cf8d498b0572b253435991f57f4e496763bbbbc3d92bd50c7f05"
                    )
            );
            assert(_withdrawer == withdrawer);
            assert(_funded == true);
        }

        assertEq(user.balance, 0);

        (, , uint256 limit, uint256 keys, uint256 funded, uint256 available, bool banned) = stakingContract.getOperator(
            operatorIndex
        );
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 1);
        assertEq(available, 9);
        assert(banned == false);
    }

    function testExplicitDepositOneValidator(uint256 _userSalt, uint256 _withdrawerSalt) public {
        address user = uf._new(_userSalt);
        address withdrawer = uf._new(_withdrawerSalt);
        vm.deal(user, 32 ether);
        vm.roll(99999);
        uint256 operatorIndex = 1;

        vm.startPrank(user);
        stakingContract.deposit{value: 32 ether}(withdrawer);
        vm.stopPrank();

        assertEq(user.balance, 0);

        (, , uint256 limit, uint256 keys, uint256 funded, uint256 available, bool banned) = stakingContract.getOperator(
            operatorIndex
        );
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 1);
        assertEq(available, 9);
        assert(banned == false);
    }

    function testExplicitDepositThreeValidators(uint256 _userSalt, uint256 _withdrawerSalt) public {
        address user = uf._new(_userSalt);
        address withdrawer = uf._new(_withdrawerSalt);
        vm.roll(99999);
        vm.deal(user, 32 * 3 ether);

        vm.startPrank(user);
        stakingContract.deposit{value: 32 * 3 ether}(withdrawer);
        vm.stopPrank();

        assertEq(user.balance, 0);

        uint256 sum;

        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool banned
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assert(banned == false);
        sum += funded;

        (operatorAddress, feeRecipientAddress, limit, keys, funded, available, banned) = stakingContract.getOperator(1);
        assertEq(operatorAddress, operatorTwo);
        assertEq(feeRecipientAddress, feeRecipientTwo);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assert(banned == false);
        sum += funded;

        (operatorAddress, feeRecipientAddress, limit, keys, funded, available, banned) = stakingContract.getOperator(2);
        assertEq(operatorAddress, operatorThree);
        assertEq(feeRecipientAddress, feeRecipientThree);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assert(banned == false);
        sum += funded;

        assert(sum == 3);
    }

    function testExplicitDepositAllValidators(uint256 _userSalt, uint256 _withdrawerSalt) public {
        address user = uf._new(_userSalt);
        address withdrawer = uf._new(_withdrawerSalt);
        vm.deal(user, 32 * 30 ether);

        vm.startPrank(user);
        stakingContract.deposit{value: 32 * 30 ether}(withdrawer);
        vm.stopPrank();

        assertEq(user.balance, 0);

        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool banned
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 10);
        assertEq(available, 0);
        assert(banned == false);

        (operatorAddress, feeRecipientAddress, limit, keys, funded, available, banned) = stakingContract.getOperator(1);
        assertEq(operatorAddress, operatorTwo);
        assertEq(feeRecipientAddress, feeRecipientTwo);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 10);
        assertEq(available, 0);
        assert(banned == false);

        (operatorAddress, feeRecipientAddress, limit, keys, funded, available, banned) = stakingContract.getOperator(2);
        assertEq(operatorAddress, operatorThree);
        assertEq(feeRecipientAddress, feeRecipientThree);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 10);
        assertEq(available, 0);
        assert(banned == false);
    }

    function testExplicitDepositNotEnough(uint256 _userSalt, uint256 _withdrawerSalt) public {
        address user = uf._new(_userSalt);
        address withdrawer = uf._new(_withdrawerSalt);
        vm.deal(user, 32 * 31 ether);

        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("NotEnoughValidators()"));
        stakingContract.deposit{value: 32 * 31 ether}(withdrawer);
        vm.stopPrank();
    }

    function testExplicitDepositNotEnoughAfterFilled(uint256 _userSalt, uint256 _withdrawerSalt) public {
        address user = uf._new(_userSalt);
        address withdrawer = uf._new(_withdrawerSalt);
        vm.deal(user, 32 * 31 ether);

        vm.startPrank(user);
        stakingContract.deposit{value: 32 * 30 ether}(withdrawer);
        vm.stopPrank();
        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("NotEnoughValidators()"));
        stakingContract.deposit{value: 32 ether}(withdrawer);
        vm.stopPrank();
    }

    function testExplicitDepositInvalidAmount(uint256 _userSalt, uint256 _withdrawerSalt) public {
        address user = uf._new(_userSalt);
        address withdrawer = uf._new(_withdrawerSalt);
        vm.deal(user, 31.9 ether);

        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("InvalidDepositValue()"));
        stakingContract.deposit{value: 31.9 ether}(withdrawer);
        vm.stopPrank();
    }

    function testImplicitDepositOneValidator(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 32 ether);
        vm.roll(99999);
        uint256 operatorIndex = 1;

        vm.startPrank(user);
        (bool _success, ) = address(stakingContract).call{value: 32 ether}("");
        assert(_success == true);
        vm.stopPrank();

        assertEq(user.balance, 0);

        (, , uint256 limit, uint256 keys, uint256 funded, uint256 available, bool banned) = stakingContract.getOperator(
            operatorIndex
        );
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 1);
        assertEq(available, 9);
        assert(banned == false);
    }

    function testImplicitDepositThreeValidators(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 32 * 3 ether);

        vm.startPrank(user);
        (bool _success, ) = address(stakingContract).call{value: 32 * 3 ether}("");
        assert(_success == true);
        vm.stopPrank();

        assertEq(user.balance, 0);
        uint256 sum;

        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool banned
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assert(banned == false);
        sum += funded;

        (operatorAddress, feeRecipientAddress, limit, keys, funded, available, banned) = stakingContract.getOperator(1);
        assertEq(operatorAddress, operatorTwo);
        assertEq(feeRecipientAddress, feeRecipientTwo);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assert(banned == false);
        sum += funded;

        (operatorAddress, feeRecipientAddress, limit, keys, funded, available, banned) = stakingContract.getOperator(2);
        assertEq(operatorAddress, operatorThree);
        assertEq(feeRecipientAddress, feeRecipientThree);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assert(banned == false);
        sum += funded;

        assert(sum == 3);
    }

    function testImplicitDepositAllValidators(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 32 * 30 ether);

        vm.startPrank(user);
        (bool _success, ) = address(stakingContract).call{value: 32 * 30 ether}("");
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
            bool banned
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 10);
        assertEq(available, 0);
        assert(banned == false);

        (operatorAddress, feeRecipientAddress, limit, keys, funded, available, banned) = stakingContract.getOperator(1);
        assertEq(operatorAddress, operatorTwo);
        assertEq(feeRecipientAddress, feeRecipientTwo);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 10);
        assertEq(available, 0);
        assert(banned == false);

        (operatorAddress, feeRecipientAddress, limit, keys, funded, available, banned) = stakingContract.getOperator(2);
        assertEq(operatorAddress, operatorThree);
        assertEq(feeRecipientAddress, feeRecipientThree);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 10);
        assertEq(available, 0);
        assert(banned == false);
    }

    function testImplicitDepositNotEnough(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 32 * 31 ether);

        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("NotEnoughValidators()"));
        (bool _success, ) = address(stakingContract).call{value: 32 * 31 ether}("");
        assert(_success == true);
        vm.stopPrank();
    }

    function testImplicitDepositNotEnoughAfterFilled(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 32 * 31 ether);

        vm.startPrank(user);
        (bool _success, ) = address(stakingContract).call{value: 32 * 30 ether}("");
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
}

contract StakingContractDistributionTest is DSTestPlus {
    Vm internal vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

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
        stakingContract = new StakingContract();
        depositContract = new DepositContractMock();
        stakingContract.initialize_1(admin, address(depositContract), address(0), address(0), 500, 500);
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

    function testDistribution(uint8 newOps, uint8 keyPerOperator) public {
        newOps = newOps % 50;
        keyPerOperator = keyPerOperator % 50;

        if (newOps < 3) {
            newOps = 3;
        }

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
            stakingContract.setOperatorLimit(i, keyPerOperator);
            vm.stopPrank();
        }

        for (uint256 i; i < depositCount; ) {
            vm.roll(i);
            uint256 availableKeys = stakingContract.getAvailableValidatorCount();
            salt = keccak256(abi.encode(salt));
            uint256 newDeposits = (uint8(salt[0]) % 31) + 1;
            if (i + newDeposits > depositCount) {
                newDeposits = (depositCount - i);
            }
            vm.deal(bob, newDeposits * 32 ether);
            vm.startPrank(bob);
            stakingContract.deposit{value: newDeposits * 32 ether}(bob);
            vm.stopPrank();
            i += newDeposits;
            assert(stakingContract.getAvailableValidatorCount() == availableKeys - newDeposits);
        }

        uint256 sum;
        uint256 availableSum;

        for (uint256 i; i < newOps; ++i) {
            (, , , , uint256 funded, uint256 available, bool banned) = stakingContract.getOperator(i);
            sum += funded;
            availableSum += available;
            assert(banned == false);
        }

        assert(depositCount == sum);
        assert(availableSum == stakingContract.getAvailableValidatorCount());
        assert(address(depositContract).balance == depositCount * 32 ether);
    }
}

contract StakingContractTwoValidatorsTest is DSTestPlus {
    Vm internal vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    StakingContract internal stakingContract;
    DepositContractMock internal depositContract;
    UserFactory internal uf;

    address internal admin = address(1);
    address internal bob = address(2);
    address internal alice = address(3);
    address internal operatorOne = address(4);
    address internal feeRecipientOne = address(44);
    address internal operatorTwo = address(5);
    address internal feeRecipientTwo = address(55);

    function setUp() public {
        uf = new UserFactory();
        stakingContract = new StakingContract();
        depositContract = new DepositContractMock();
        stakingContract.initialize_1(admin, address(depositContract), address(0), address(0), 500, 500);

        vm.startPrank(admin);
        stakingContract.addOperator(operatorOne, feeRecipientOne);
        stakingContract.addOperator(operatorTwo, feeRecipientTwo);
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
            bytes
                memory publicKeys = hex"24046f7be8644e2b872363d5a4d58836deeb2deab6996a7e57f8c7583872786d1b81e378c4188ec3094236a31e31bd83c89e108b2d2e26e9dba2cc7a4f898c5f4b62d43f8e76c7cf64d02aab46afc436d7759d2b2e4d4aca97687b0022bec98307d1b050eafad3ba0fdf22cf645936ebd9e3c1ae913badc7307e02c38d778b10259b571237cc826a030b44a4fd53da790a84e6578890a7c801bbc2212bfccfecf88da5203e96c29b404fd9a61400f808e11a10fe39c9d97de43ad20867b3f5a71cc86d46d1058ab033c63c2369774cabe009231a85836abe39f9f5b41158a2505305d6e500cd64eb8e479e59c72945b9aaa177fd4a99d36dac27400609e098b8ce8638dc0ae641043107e47ccc495bdf7f40811e1c67103605241ea329ebd34e85d3184f79fe2b4642007709c2f4912853d72e0399930a62c915e50d4e1a1bd0fa26f021f37f519b86e168a181604c9c4b9af621932f09601bd9d5d0a9ee349076765d1baea4eef0fc16d4ebc861569ec37857c1d654ca442d2b0c85e97c5d56289a42afa5040cb1901bd03faf7011780599ed2cf826b8a2dd9deece7d9ecd7d7be2751bb42645f0253732447092311597a0f7672268125a95464c541e7fb1e3e08151f038adec85a60db0a9a9430ca80ffdbabe557aa2e0f69e6aed98527c91";
            bytes
                memory signatures = hex"57412124b1730be9e30a395b5e7af34e7cecd16b8cc3a5b255f7b5e5cd92a3aa328401d07268d0ffaed8867d8a6288e569c547506b3f124f45f37d17bf0ec9c55917db458ba9cf8d498b0572b253435991f57f4e496763bbbbc3d92bd50c7f05304112ec1a45d0a8e5b3aa309dc4377ee8beb9d79b08f6bd60d0696b29acff9539cb836f2f00bbf888cfd28e4cfa4f317d6c3babdc0e121247789137eae3553de0c67ccbe2a5135f8f70dc5a79023544da8d608c825ef06ec32d315b4b026dd8f7f667af7368efead94f6f38418b1527a7c4500424410b8b09c580e89bc8cfba27eed8cea56311b9446313de80bb24f09072ee0ef5ceb504d7bdefed1e3fa5a8aee876b44302f7ff1b8a039033c3ed370a7b02a0cc23a5b7b4d7499649e6ee3f37d51fcbde910f6d10c1512eaf8924a8c7f150d280efb293e719ff07357c01482b1b6cc75a3d0118bdc058cccf67fbcbaad1423f2940d0191bb1d8257a2d827e74a3963ccbd316081105be05e8471d8fa466b4935c0dce7cb6bcb36dd1ef2a156841be9793a00a3aefb8e55ef91f6f17ba49cb9025dc441fd381ad5194de34d9032df1f26930537f0fcd509638403c3ce8df19f2106904cfd82e92627283fdc8ac5165848dabbf1b1566302ddeb72f70a17bb1520b8cc3b41c007e3bf334af34e900ef5fc0b3fb8642f7bd0b109c7cfd204c7e0039c10d1592ec02e8af9ea9653df70fed29d30c2784e3ff187caabb0a588db0fd2bb77565909cd5f5895a56d32510fb90735d5f1ca1dd4b9bbf7ce3e8d3745a879093e90d883875b865a69d7b79b2bf4cf42cedf084447c95e31d11c41adff8a9939550c87996d7f4002c9064bb2e6e675310caf556a7e44f07e92704c7589c2e335cbd4dc3fde2bfd7d79ad050bee3066e5aed5e97c445e0c54c9f5c5febbc5182aeaad91acc0e9b58bfed9049a2ccc09bf4b2534220f24c8c387306a498fffe66d3cd50c34296fb456fe2656999893ed1ac5ed8eb1845455412833e9abec7274714ccbef2c20172df5fdde1e1bb142c5987c8aec208fb11b383cf4b1c3851d8ef27561176605487b5c83923fa731e94ee6ec59fe8307df91c2552a1e318933f32c9b2f27896f932c69b9dc0c8860e78663a5be9480be01b19bc9f56b955e442af493f0d267d4ed8e466eaa345af4e476beade96d6460a4e701c1604f190eafc6c42ed751943cb7393b7bb871c9849f056bddf731fb1eed5b8f030330d245834834994f49d1ecb6eac952e02baa1298f482b622caaa4b6479afd6729cfc2c14ab571e4d32973016cded551becd595af5bcb1cf53db1b55ca1b580da6564f065ac8c8c1709ccdc30003125d54";

            vm.startPrank(operatorTwo);
            stakingContract.addValidators(1, 10, publicKeys, signatures);
            vm.stopPrank();
        }

        {
            vm.startPrank(admin);
            stakingContract.setOperatorLimit(0, 10);
            stakingContract.setOperatorLimit(1, 10);
            vm.stopPrank();
        }
    }

    event Deposit(address indexed caller, address indexed withdrawer, bytes publicKey, bytes32 publicKeyRoot);

    function testExplicitDepositOneValidator(uint256 _userSalt, uint256 _withdrawerSalt) public {
        address user = uf._new(_userSalt);
        address withdrawer = uf._new(_withdrawerSalt);
        vm.deal(user, 32 ether);

        vm.roll(99999);

        vm.startPrank(user);
        stakingContract.deposit{value: 32 ether}(withdrawer);
        vm.stopPrank();

        assertEq(user.balance, 0);

        (, , uint256 limit, uint256 keys, uint256 funded, uint256 available, bool banned) = stakingContract.getOperator(
            0
        );
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 1);
        assertEq(available, 9);
        assert(banned == false);
    }

    function testExplicitDepositTwoValidators(uint256 _userSalt, uint256 _withdrawerSalt) public {
        address user = uf._new(_userSalt);
        address withdrawer = uf._new(_withdrawerSalt);
        vm.deal(user, 32 * 2 ether);

        vm.startPrank(user);
        vm.expectEmit(true, true, true, true);
        emit Deposit(
            user,
            withdrawer,
            hex"24046f7be8644e2b872363d5a4d58836deeb2deab6996a7e57f8c7583872786d1b81e378c4188ec3094236a31e31bd83",
            bytes32(0x97e0fcc0cd21a2beb0f53a4f824b6eeb7297c74a3b8dafb2b56cd870ece6ee56)
        );
        stakingContract.deposit{value: 32 * 2 ether}(withdrawer);
        vm.stopPrank();

        assertEq(user.balance, 0);

        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool banned
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 1);
        assertEq(available, 9);
        assert(banned == false);

        (operatorAddress, feeRecipientAddress, limit, keys, funded, available, banned) = stakingContract.getOperator(1);
        assertEq(operatorAddress, operatorTwo);
        assertEq(feeRecipientAddress, feeRecipientTwo);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 1);
        assertEq(available, 9);
        assert(banned == false);
    }

    function testExplicitDepositAllValidators(uint256 _userSalt, uint256 _withdrawerSalt) public {
        address user = uf._new(_userSalt);
        address withdrawer = uf._new(_withdrawerSalt);
        vm.deal(user, 32 * 20 ether);

        vm.startPrank(user);
        stakingContract.deposit{value: 32 * 20 ether}(withdrawer);
        vm.stopPrank();

        assertEq(user.balance, 0);

        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool banned
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 10);
        assertEq(available, 0);
        assert(banned == false);

        (operatorAddress, feeRecipientAddress, limit, keys, funded, available, banned) = stakingContract.getOperator(1);
        assertEq(operatorAddress, operatorTwo);
        assertEq(feeRecipientAddress, feeRecipientTwo);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 10);
        assertEq(available, 0);
        assert(banned == false);
    }

    function testExplicitDepositNotEnough(uint256 _userSalt, uint256 _withdrawerSalt) public {
        address user = uf._new(_userSalt);
        address withdrawer = uf._new(_withdrawerSalt);
        vm.deal(user, 32 * 21 ether);

        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("NotEnoughValidators()"));
        stakingContract.deposit{value: 32 * 21 ether}(withdrawer);
        vm.stopPrank();
    }

    function testExplicitDepositNotEnoughAfterFilled(uint256 _userSalt, uint256 _withdrawerSalt) public {
        address user = uf._new(_userSalt);
        address withdrawer = uf._new(_withdrawerSalt);
        vm.deal(user, 32 * 21 ether);

        vm.startPrank(user);
        stakingContract.deposit{value: 32 * 20 ether}(withdrawer);
        vm.stopPrank();
        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("NotEnoughValidators()"));
        stakingContract.deposit{value: 32 ether}(withdrawer);
        vm.stopPrank();
    }

    function testExplicitDepositInvalidAmount(uint256 _userSalt, uint256 _withdrawerSalt) public {
        address user = uf._new(_userSalt);
        address withdrawer = uf._new(_withdrawerSalt);
        vm.deal(user, 31.9 ether);

        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("InvalidDepositValue()"));
        stakingContract.deposit{value: 31.9 ether}(withdrawer);
        vm.stopPrank();
    }

    function testImplicitDepositOneValidator(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 32 ether);

        vm.roll(1000);

        vm.startPrank(user);
        (bool _success, ) = address(stakingContract).call{value: 32 ether}("");
        assert(_success == true);
        vm.stopPrank();

        assertEq(user.balance, 0);

        (, , uint256 limit, uint256 keys, uint256 funded, uint256 available, bool banned) = stakingContract.getOperator(
            1
        );
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 1);
        assertEq(available, 9);
        assert(banned == false);
    }

    function testImplicitDepositTwoValidators(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 32 * 2 ether);

        vm.startPrank(user);
        vm.expectEmit(true, true, true, true);
        emit Deposit(
            user,
            user,
            hex"24046f7be8644e2b872363d5a4d58836deeb2deab6996a7e57f8c7583872786d1b81e378c4188ec3094236a31e31bd83",
            bytes32(0x97e0fcc0cd21a2beb0f53a4f824b6eeb7297c74a3b8dafb2b56cd870ece6ee56)
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
            bool banned
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 1);
        assertEq(available, 9);
        assert(banned == false);

        (operatorAddress, feeRecipientAddress, limit, keys, funded, available, banned) = stakingContract.getOperator(1);
        assertEq(operatorAddress, operatorTwo);
        assertEq(feeRecipientAddress, feeRecipientTwo);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 1);
        assertEq(available, 9);
        assert(banned == false);
    }

    function testImplicitDepositAllValidators(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 32 * 20 ether);

        vm.startPrank(user);
        (bool _success, ) = address(stakingContract).call{value: 32 * 20 ether}("");
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
            bool banned
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 10);
        assertEq(available, 0);
        assert(banned == false);

        (operatorAddress, feeRecipientAddress, limit, keys, funded, available, banned) = stakingContract.getOperator(1);
        assertEq(operatorAddress, operatorTwo);
        assertEq(feeRecipientAddress, feeRecipientTwo);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 10);
        assertEq(available, 0);
        assert(banned == false);
    }

    function testImplicitDepositNotEnough(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 32 * 21 ether);

        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("NotEnoughValidators()"));
        (bool _success, ) = address(stakingContract).call{value: 32 * 21 ether}("");
        assert(_success == true);
        vm.stopPrank();
    }

    function testImplicitDepositNotEnoughAfterFilled(uint256 _userSalt) public {
        address user = uf._new(_userSalt);
        vm.deal(user, 32 * 21 ether);

        vm.startPrank(user);
        (bool _success, ) = address(stakingContract).call{value: 32 * 20 ether}("");
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
}

contract StakingContractOneValidatorTest is DSTestPlus {
    Vm internal vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    StakingContract internal stakingContract;
    DepositContractMock internal depositContract;
    UserFactory internal uf;

    address internal admin = address(1);
    address internal bob = address(2);
    address internal alice = address(3);
    address internal operatorOne = address(4);
    address internal feeRecipientOne = address(44);
    ExecutionLayerFeeRecipient internal elfr;
    ConsensusLayerFeeRecipient internal clfr;

    function setUp() public {
        uf = new UserFactory();
        stakingContract = new StakingContract();
        depositContract = new DepositContractMock();
        elfr = new ExecutionLayerFeeRecipient(1);
        clfr = new ConsensusLayerFeeRecipient(1);
        stakingContract.initialize_1(admin, address(depositContract), address(elfr), address(clfr), 500, 500);

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
            stakingContract.setOperatorLimit(0, 10);
            vm.stopPrank();
        }
    }

    event Deposit(address indexed caller, address indexed withdrawer, bytes publicKey, bytes32 publicKeyRoot);
    event DepositEvent(bytes pubkey, bytes withdrawal_credentials, bytes amount, bytes signature, bytes index);

    function testExplicitDepositOneValidatorCheckDepositEvent(uint256 _userSalt, uint256 _withdrawerSalt) public {
        address user = uf._new(_userSalt);
        address withdrawer = uf._new(_withdrawerSalt);
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
        stakingContract.deposit{value: 32 ether}(withdrawer);
        vm.stopPrank();

        assertEq(user.balance, 0);

        (, , uint256 limit, uint256 keys, uint256 funded, uint256 available, bool banned) = stakingContract.getOperator(
            0
        );
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 1);
        assertEq(available, 9);
        assert(banned == false);
    }

    function testExplicitDepositOneValidator(uint256 _userSalt, uint256 _withdrawerSalt) public {
        address user = uf._new(_userSalt);
        address withdrawer = uf._new(_withdrawerSalt);
        vm.deal(user, 32 ether);

        vm.startPrank(user);
        stakingContract.deposit{value: 32 ether}(withdrawer);
        vm.stopPrank();

        assertEq(user.balance, 0);

        (, , uint256 limit, uint256 keys, uint256 funded, uint256 available, bool banned) = stakingContract.getOperator(
            0
        );
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 1);
        assertEq(available, 9);
        assert(banned == false);
    }

    function testExplicitDepositTwoValidators(uint256 _userSalt, uint256 _withdrawerSalt) public {
        address user = uf._new(_userSalt);
        address withdrawer = uf._new(_withdrawerSalt);
        vm.deal(user, 32 * 2 ether);

        vm.startPrank(user);
        vm.expectEmit(true, true, true, true);
        emit Deposit(
            user,
            withdrawer,
            hex"b0ce3fa164aae897adca509ed44429e7b1f91b7c46ddbe199cee848e09b1ccbb9736b78b68aacff1011b7266fe11e060",
            bytes32(0xf01ffef8921186d42b508056be28fc1b50c6f3268645d82aba851f341c7e03d4)
        );
        stakingContract.deposit{value: 32 * 2 ether}(withdrawer);
        vm.stopPrank();

        assertEq(user.balance, 0);

        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool banned
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 2);
        assertEq(available, 8);
        assert(banned == false);
    }

    function testExplicitDepositAllValidators(uint256 _userSalt, uint256 _withdrawerSalt) public {
        address user = uf._new(_userSalt);
        address withdrawer = uf._new(_withdrawerSalt);
        vm.deal(user, 32 * 10 ether);

        vm.startPrank(user);
        stakingContract.deposit{value: 32 * 10 ether}(withdrawer);
        vm.stopPrank();

        assertEq(user.balance, 0);

        (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool banned
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 10);
        assertEq(available, 0);
        assert(banned == false);
    }

    function testExplicitDepositNotEnough(uint256 _userSalt, uint256 _withdrawerSalt) public {
        address user = uf._new(_userSalt);
        address withdrawer = uf._new(_withdrawerSalt);
        vm.deal(user, 32 * 11 ether);

        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("NotEnoughValidators()"));
        stakingContract.deposit{value: 32 * 11 ether}(withdrawer);
        vm.stopPrank();
    }

    function testExplicitDepositNotEnoughAfterFilled(uint256 _userSalt, uint256 _withdrawerSalt) public {
        address user = uf._new(_userSalt);
        address withdrawer = uf._new(_withdrawerSalt);
        vm.deal(user, 32 * 11 ether);

        vm.startPrank(user);
        stakingContract.deposit{value: 32 * 10 ether}(withdrawer);
        vm.stopPrank();
        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("NotEnoughValidators()"));
        stakingContract.deposit{value: 32 ether}(withdrawer);
        vm.stopPrank();
    }

    function testExplicitDepositInvalidAmount(uint256 _userSalt, uint256 _withdrawerSalt) public {
        address user = uf._new(_userSalt);
        address withdrawer = uf._new(_withdrawerSalt);
        vm.deal(user, 31.9 ether);

        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSignature("InvalidDepositValue()"));
        stakingContract.deposit{value: 31.9 ether}(withdrawer);
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

        (, , uint256 limit, uint256 keys, uint256 funded, uint256 available, bool banned) = stakingContract.getOperator(
            0
        );
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 1);
        assertEq(available, 9);
        assert(banned == false);
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
            bytes32(0xf01ffef8921186d42b508056be28fc1b50c6f3268645d82aba851f341c7e03d4)
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
            bool banned
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 2);
        assertEq(available, 8);
        assert(banned == false);
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
            bool banned
        ) = stakingContract.getOperator(0);
        assertEq(operatorAddress, operatorOne);
        assertEq(feeRecipientAddress, feeRecipientOne);
        assertEq(limit, 10);
        assertEq(keys, 10);
        assertEq(funded, 10);
        assertEq(available, 0);
        assert(banned == false);
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

    function testEditELFee() public {
        assert(stakingContract.getELFee() == 500);
        vm.startPrank(admin);
        stakingContract.setELFee(1000);
        vm.stopPrank();
        assert(stakingContract.getELFee() == 1000);
    }

    function testEditCLFee() public {
        assert(stakingContract.getCLFee() == 500);
        vm.startPrank(admin);
        stakingContract.setCLFee(1000);
        vm.stopPrank();
        assert(stakingContract.getCLFee() == 1000);
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
        stakingContract.deposit{value: 32 ether}(bob);
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(publicKey);
        assert(elfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);
        vm.deal(address(elfrBob), 1 ether);
        stakingContract.withdrawELFee(publicKey);
        assert(elfrBob.code.length != 0);
        assert(bob.balance == 0.95 ether);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0.05 ether);
    }

    function testWithdrawELFeesEditedFeeBps() public {
        vm.startPrank(admin);
        stakingContract.setELFee(1000);
        vm.stopPrank();
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}(bob);
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(publicKey);
        assert(elfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);
        vm.deal(address(elfrBob), 1 ether);
        stakingContract.withdrawELFee(publicKey);
        assert(elfrBob.code.length != 0);
        assert(bob.balance == 0.9 ether);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0.1 ether);
    }

    function testWithdrawELFeesAlreadyDeployed() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}(bob);
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address elfrBob = stakingContract.getELFeeRecipient(publicKey);
        assert(elfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);
        vm.deal(address(elfrBob), 1 ether);
        stakingContract.withdrawELFee(publicKey);
        assert(elfrBob.code.length != 0);
        assert(bob.balance == 0.95 ether);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0.05 ether);
        vm.deal(address(elfrBob), 1 ether);
        stakingContract.withdrawELFee(publicKey);
        assert(bob.balance == 1.90 ether);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0.1 ether);
    }

    function testWithdrawELFeesEmptyWithdrawal() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}(bob);
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        vm.expectRevert(abi.encodeWithSignature("ZeroBalanceWithdrawal()"));
        stakingContract.withdrawELFee(publicKey);
    }

    function testWithdrawCLFeesExitedValidator() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}(bob);
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);
        vm.deal(address(clfrBob), 33 ether);
        stakingContract.withdrawCLFee(publicKey);
        assert(clfrBob.code.length != 0);
        assert(bob.balance == 32.95 ether);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0.05 ether);
    }

    function testWithdrawCLFeesEditedFeeBps() public {
        vm.startPrank(admin);
        stakingContract.setCLFee(1000);
        vm.stopPrank();
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}(bob);
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);
        vm.deal(address(clfrBob), 33 ether);
        stakingContract.withdrawCLFee(publicKey);
        assert(clfrBob.code.length != 0);
        assert(bob.balance == 32.90 ether);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0.1 ether);
    }

    function testWithdrawCLFeesSkimmedValidator() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}(bob);
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);
        vm.deal(address(clfrBob), 1 ether);
        stakingContract.withdrawCLFee(publicKey);
        assert(clfrBob.code.length != 0);
        assert(bob.balance == 0.95 ether);
        assert(feeRecipientOne.balance == 0.05 ether);
        assert(operatorOne.balance == 0);
    }

    function testWithdrawCLFeesSlashedValidator() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}(bob);
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        vm.deal(address(clfrBob), 31.95 ether);
        stakingContract.withdrawCLFee(publicKey);
        assert(clfrBob.code.length != 0);
        assert(bob.balance == 31.95 ether);
        assert(operatorOne.balance == 0);
    }

    function testWithdrawCLFeesAlreadyDeployed() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}(bob);
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        address clfrBob = stakingContract.getCLFeeRecipient(publicKey);
        assert(clfrBob.code.length == 0);
        assert(bob.balance == 0);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0);
        vm.deal(address(clfrBob), 33 ether);
        stakingContract.withdrawCLFee(publicKey);
        assert(clfrBob.code.length != 0);
        assert(bob.balance == 32.95 ether);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0.05 ether);
        vm.deal(address(clfrBob), 1 ether);
        stakingContract.withdrawCLFee(publicKey);
        assert(bob.balance == 33.9 ether);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0.1 ether);
    }

    function testWithdrawCLFeesEmptyWithdrawal() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}(bob);
        assert(stakingContract.getWithdrawer(publicKey) == bob);
        vm.stopPrank();
        vm.expectRevert(abi.encodeWithSignature("ZeroBalanceWithdrawal()"));
        stakingContract.withdrawCLFee(publicKey);
    }

    function testWithdrawAllFees() public {
        bytes
            memory publicKey = hex"21d2e725aef3a8f9e09d8f4034948bb7f79505fc7c40e7a7ca15734bad4220a594bf0c6257cef7db88d9fc3fd4360759";
        vm.deal(bob, 32 ether);
        vm.startPrank(bob);
        stakingContract.deposit{value: 32 ether}(bob);
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

        stakingContract.withdraw(publicKey);

        assert(bob.balance == 33.9 ether);
        assert(operatorOne.balance == 0);
        assert(feeRecipientOne.balance == 0.1 ether);
    }
}
