//SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.10;

import {TUPProxy} from "../../contracts/TUPProxy.sol";
import {StakingContract} from "../../contracts/StakingContract.sol";
import {Test} from "forge-std/Test.sol";

interface HexagateOracle {
    function isSanctioned(address) external returns (bool);

    function addToAllowList(address) external;

    function removeFromAllowList(address) external;

    function hasRole(bytes32, address) external returns (bool);
}

contract Test_1_3__FORK is Test {
    StakingContract ledgerLive = StakingContract(payable(address(0x1e68238cE926DEC62b3FBC99AB06eB1D85CE0270)));
    address ledgerLiveAdmin = address(0xCf53Ef5be9C713585D2fEF40e72D9c7C4fE1D5F2);
    address ledgerLiveProxyAdmin = address(0xd235d4Eb3A483743C506C8AB6ee50f4eBfDEF4D8);

    StakingContract kilnDApp = StakingContract(payable(address(0xEF650d5DbE75f39e2ec18A4381F75c8a4D4E19C8)));
    address kilnDAppAdmin = address(0xc1cAf43fB9ac723feF07Ea94A1C423880cdf5301);
    address kilnDAppProxyAdmin = address(0x60CFAC5cD4aEed165023A81F57A0bc92D7CfEb6E);

    StakingContract Enzyme = StakingContract(payable(address(0x0816DF553a89c4bFF7eBfD778A9706a989Dd3Ce3)));
    address EnzymeAdmin = address(0x45DAD754897ef0b2780349AD7c7000c72717b24E);
    address EnzymeProxyAdmin = address(0xb270FE91e8E4b80452fBF1b4704208792A350f53);

    address oracleGatewayAdmin = address(0xc1cAf43fB9ac723feF07Ea94A1C423880cdf5301);

    address oracleChainalysis = address(0x40C57923924B5c5c5455c48D93317139ADDaC8fb);
    address oracleGatewayHexagate = address(0xc8707753881033e1525f3c3CA1C3e547D00d8315);

    address implem_1_3 = address(0x27496261007D0F7ceBb3645914579d899EB25f9f);

    address alice;

    function setUp() public {
        vm.createSelectFork(vm.rpcUrl("MAINNET"), 22045538);

        alice = makeAddr("alice");
        vm.deal(alice, 100 ether);
    }

    // Ledger Live
    function test_getAdmin_LedgerLive() public {
        verifyAdmin(ledgerLive, ledgerLiveAdmin);
    }

    function test_1_3_LedgerLive() public {
        _testUpgrade(ledgerLive, ledgerLiveProxyAdmin, implem_1_3);
    }

    function test_1_3_LedgerLive_set_oracle_deposit() public {
        _test_upgrade_set_oracle_deposit(ledgerLive, ledgerLiveAdmin, ledgerLiveProxyAdmin, implem_1_3);
    }

    function test_1_3_LedgerLive_set_hexagate_oracle_deposit() public {
        _test_upgrade_set_hexagate_oracle_deposit(
            ledgerLive,
            ledgerLiveAdmin,
            ledgerLiveProxyAdmin,
            implem_1_3,
            oracleGatewayHexagate
        );
    }

    // Kiln DApp
    function test_getAdmin_KilnDApp() public {
        verifyAdmin(kilnDApp, kilnDAppAdmin);
    }

    function test_1_3_KilnDApp() public {
        _testUpgrade(kilnDApp, kilnDAppProxyAdmin, implem_1_3);
    }

    function test_1_3_KilnDApp_set_oracle_deposit() public {
        _test_upgrade_set_oracle_deposit(kilnDApp, kilnDAppAdmin, kilnDAppProxyAdmin, implem_1_3);
    }

    function test_1_3_KilnDApp_set_hexagate_oracle_deposit() public {
        _test_upgrade_set_hexagate_oracle_deposit(
            kilnDApp,
            kilnDAppAdmin,
            kilnDAppProxyAdmin,
            implem_1_3,
            oracleGatewayHexagate
        );
    }

    // Enzyme
    function test_getAdmin_Enzyme() public {
        verifyAdmin(Enzyme, EnzymeAdmin);
    }

    function test_1_3_Enzyme() public {
        _testUpgrade(Enzyme, EnzymeProxyAdmin, implem_1_3);
    }

    function test_1_3_Enzyme_set_oracle_deposit() public {
        _test_upgrade_set_oracle_deposit(Enzyme, EnzymeAdmin, EnzymeProxyAdmin, implem_1_3);
    }

    function test_1_3_Enzyme_set_hexagate_oracle_deposit() public {
        _test_upgrade_set_hexagate_oracle_deposit(
            Enzyme,
            EnzymeAdmin,
            EnzymeProxyAdmin,
            implem_1_3,
            oracleGatewayHexagate
        );
    }

    // UTILS

    function _testUpgrade(
        StakingContract stakingContract,
        address proxy_admin,
        address implem13
    ) public {
        vm.expectRevert();
        assertEq(stakingContract.getSanctionsOracle(), address(0));

        vm.prank(proxy_admin);
        TUPProxy(payable(address(stakingContract))).upgradeTo(implem13);

        // assert upgrade was successful
        assertEq(stakingContract.getSanctionsOracle(), address(0));

        // users can still deposit
        vm.prank(alice);
        stakingContract.deposit{value: 32 ether}();
    }

    function _test_upgrade_set_oracle_deposit(
        StakingContract target,
        address admin,
        address proxy_admin,
        address implem13
    ) public {
        vm.prank(proxy_admin);
        TUPProxy(payable(address(target))).upgradeTo(implem13);

        // assert we are interacting with the new implementation, would revert if not
        assertEq(target.getSanctionsOracle(), address(0));

        vm.prank(admin);
        target.setSanctionsOracle(oracleChainalysis);

        assertEq(target.getSanctionsOracle(), oracleChainalysis);

        vm.prank(alice);
        target.deposit{value: 32 ether}();
    }

    function _test_upgrade_set_hexagate_oracle_deposit(
        StakingContract target,
        address admin,
        address proxy_admin,
        address implem13,
        address oracleGateway
    ) public {
        // Upgrade to 1.3
        vm.prank(proxy_admin);
        TUPProxy(payable(address(target))).upgradeTo(implem13);

        vm.prank(alice);
        target.deposit{value: 32 ether}();

        // Add deployment to allow list
        vm.prank(oracleGatewayAdmin);
        HexagateOracle(oracleGateway).addToAllowList(address(target));

        // Set oracle on deployment
        vm.prank(admin);
        target.setSanctionsOracle(oracleGateway);

        assertEq(target.getSanctionsOracle(), oracleGateway);

        // A non-sanctioned user can still deposit
        vm.prank(alice);
        target.deposit{value: 32 ether}();
    }

    function verifyAdmin(StakingContract target, address admin) public {
        assertEq(target.getAdmin(), admin);
    }
}
