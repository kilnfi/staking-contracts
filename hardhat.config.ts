import { HardhatUserConfig } from "hardhat/types";
import '@nomiclabs/hardhat-ethers';
import "hardhat-deploy";
import '@primitivefi/hardhat-dodoc';

/**
 * @type import('hardhat/config').HardhatUserConfig
 */
const hhuc: HardhatUserConfig = {
  solidity: {
    version: "0.8.13",
    settings: {
      optimizer: {
        enabled: true,
        runs: 3000,
      }
    }
  },
  paths: {
    sources: "./src/contracts",
  },
  networks: {
    // SAFE
    mainnet_safe: {
      url: process.env.RPC_URL || "",
      accounts: [process.env.PK || ""],
    },
    mainnet_2_safe: {
      url: process.env.RPC_URL || "",
      accounts: [process.env.PK || ""],
    },
    holesky_dev_safe: {
      url: process.env.RPC_URL || "",
      accounts: [process.env.PK || ""],
    },
    hoodi_test_safe: {
      url: process.env.RPC_URL || "",
      accounts: [process.env.PK || ""],
    },
    // CONSENSYS
    goerli_consensys: {
      url: process.env.RPC_URL || "",
      accounts: [process.env.PK || ""],
    },
    mainnet_consensys: {
      url: process.env.RPC_URL || "",
      accounts: [process.env.PK || ""],
    },
    goerli_dev_consensys: {
      url: process.env.RPC_URL || "",
      accounts: [process.env.PK || ""],
    },
    goerli_uat_consensys: {
      url: process.env.RPC_URL || "",
      accounts: [process.env.PK || ""],
    },
    holesky_dev_consensys: {
      url: process.env.RPC_URL || "",
      accounts: [process.env.PK || ""],
    },
    holesky_uat_consensys: {
      url: process.env.RPC_URL || "",
      accounts: [process.env.PK || ""],
    },
    goerli_consensys_dev: {
      url: process.env.RPC_URL || "",
      accounts: {
        mnemonic: process.env.MNEMONIC || "",
      },
    },
    hoodi_dev_consensys: {
      url: process.env.RPC_URL || "",
      accounts: [process.env.PK || ""],
    },
    hoodi_uat_consensys: {
      url: process.env.RPC_URL || "",
      accounts: [process.env.PK || ""],
    },
    // LEDGER
    goerli_vault: {
      url: process.env.RPC_URL || "",
      accounts: [process.env.PK || ""],
    },
    goerli_live: {
      url: process.env.RPC_URL || "",
      accounts: [process.env.PK || ""],
    },
    mainnet_vault: {
      url: process.env.RPC_URL || "",
      accounts: [process.env.PK || ""],
    },
    mainnet_live: {
      url: process.env.RPC_URL || "",
      accounts: [process.env.PK || ""],
    },
    mainnet_enzyme: {
      url: process.env.RPC_URL || "",
      accounts: [process.env.PK || ""],
    },
    // KILN
    mainnet_komainu: {
      url: process.env.RPC_URL || "",
      accounts: [process.env.PK || ""],
    },
    holesky_devnet: {
      url: process.env.RPC_URL || "",
      accounts: [process.env.PK || ""],
    },
    holesky_testnet: {
      url: process.env.RPC_URL || "",
      accounts: [process.env.PK || ""],
    },
    hoodi_devnet: {
      url: process.env.RPC_URL || "",
      accounts: [process.env.PK || ""],
    },
    hoodi_testnet: {
      url: process.env.RPC_URL || "",
      accounts: [process.env.PK || ""],
    },
  },
  dodoc: {
    include: [
      "StakingContract",
      "ConsensusLayerFeeDispatcher",
      "ExecutionLayerFeeDispatcher",
      "FeeRecipient",
    ],
    outputDir: 'natspec'
  },
  namedAccounts: {
    deployer: {
      default: 0
    },
    proxyAdmin: {
      default: 1,
      goerli_consensys: "0x938e1682fBcd30149f547eca7688ed00724AC3bF",
      goerli_consensys_dev: "0x938e1682fBcd30149f547eca7688ed00724AC3bF",
      goerli_vault: "0x3B9B2C07eff60aC828117C997E04c61890Ad2Ed7",
      goerli_live: "0x3B9B2C07eff60aC828117C997E04c61890Ad2Ed7",
      mainnet_vault: "0x3c69D70ea8487a7E64127a6Eae194ada4C144318",
      mainnet_live: "0xd235d4Eb3A483743C506C8AB6ee50f4eBfDEF4D8",
      mainnet_enzyme: "0xb270FE91e8E4b80452fBF1b4704208792A350f53",
      mainnet_komainu: "0xd235d4Eb3A483743C506C8AB6ee50f4eBfDEF4D8",
      holesky_devnet: "0xbA8E90E82ae33EBf6ab1c451Fe135546E86D0Eab",
      holesky_testnet: "0xb597001A2bEC560cBD73a1F02eBfDb86b42aC71B",
      hoodi_devnet: "0xFfFff2A646d204FB4aD6FCC4c3c53121491eBF3c",
      hoodi_testnet: "0xFfFff2A646d204FB4aD6FCC4c3c53121491eBF3c",
    },
    admin: {
      default: 2,
      goerli_consensys: "0x4Cb0De8A79C766C478742666d024A16E3e81aAE0",
      goerli_dev_consensys: "0xFb0961bea75145bC62fB6A53bE9Be70A0A7D206E",
      goerli_uat_consensys: "0xFb0961bea75145bC62fB6A53bE9Be70A0A7D206E",
      holesky_dev_consensys: "0xe8e738c2F1C383aB8282EbE30579118EC9CE4534",
      holesky_uat_consensys: "0xe8e738c2F1C383aB8282EbE30579118EC9CE4534",
      hoodi_dev_consensys: "0xd23D393167e391e62d464CD5ef09e52Ed58BC889",
      hoodi_uat_consensys: "0xd23D393167e391e62d464CD5ef09e52Ed58BC889",
      goerli_consensys_dev: "0x4Cb0De8A79C766C478742666d024A16E3e81aAE0",
      goerli_vault: "0xC4b8469165d0A0e0939500BdeCE7c0CD3415a9fb",
      goerli_live: "0xC4b8469165d0A0e0939500BdeCE7c0CD3415a9fb",
      mainnet_vault: "0xD3269B4daBd8AA336155F741C534CBAC87526A8E",
      mainnet_live: "0xCf53Ef5be9C713585D2fEF40e72D9c7C4fE1D5F2",
      mainnet_enzyme: "0x45DAD754897ef0b2780349AD7c7000c72717b24E",
      mainnet_komainu: "0xCf53Ef5be9C713585D2fEF40e72D9c7C4fE1D5F2",
      mainnet_consensys: "0x5Bc5ec5130f66f13d5C21ac6811A7e624ED3C7c6",
      mainnet_safe: "0x60CFAC5cD4aEed165023A81F57A0bc92D7CfEb6E",
      mainnet_2_safe: "0x60CFAC5cD4aEed165023A81F57A0bc92D7CfEb6E",
      holesky_devnet: "0xb3eb29AC481FCFAFA7008A4acf04737c7d6733EA",
      holesky_testnet: "0xe6fe1936Fa8120e57c7Dee1733693B59b392672c",
      holesky_dev_safe: "0xdA53Ce2F763A3270638127CEA2826e32Cd3428e5",
      hoodi_dev_safe: "0xdA53Ce2F763A3270638127CEA2826e32Cd3428e5", // TODO CONFIRM
      hoodi_devnet: "0xaAAAa6288ad901050051F282C48527628219Bf59",
      hoodi_testnet: "0xaAAAa6288ad901050051F282C48527628219Bf59",
    },
    depositContract: {
      default: 4,
      goerli_consensys: "0xff50ed3d0ec03ac01d4c79aad74928bff48a7b2b",
      goerli_dev_consensys: "0xff50ed3d0ec03ac01d4c79aad74928bff48a7b2b",
      goerli_uat_consensys: "0xff50ed3d0ec03ac01d4c79aad74928bff48a7b2b",
      goerli_consensys_dev: "0xff50ed3d0ec03ac01d4c79aad74928bff48a7b2b",
      holesky_dev_consensys: "0x4242424242424242424242424242424242424242",
      holesky_uat_consensys: "0x4242424242424242424242424242424242424242",
      hoodi_dev_consensys: "0x00000000219ab540356cBB839Cbe05303d7705Fa",
      hoodi_uat_consensys: "0x00000000219ab540356cBB839Cbe05303d7705Fa",
      goerli_vault: "0xff50ed3d0ec03ac01d4c79aad74928bff48a7b2b",
      goerli_live: "0xff50ed3d0ec03ac01d4c79aad74928bff48a7b2b",
      mainnet_vault: "0x00000000219ab540356cBB839Cbe05303d7705Fa",
      mainnet_live: "0x00000000219ab540356cBB839Cbe05303d7705Fa",
      mainnet_enzyme: "0x00000000219ab540356cBB839Cbe05303d7705Fa",
      mainnet_komainu: "0x00000000219ab540356cBB839Cbe05303d7705Fa",
      mainnet_consensys: "0x00000000219ab540356cBB839Cbe05303d7705Fa",
      mainnet_safe: "0x00000000219ab540356cBB839Cbe05303d7705Fa",
      mainnet_2_safe: "0x00000000219ab540356cBB839Cbe05303d7705Fa",
      holesky_devnet: "0x4242424242424242424242424242424242424242",
      holesky_testnet: "0x4242424242424242424242424242424242424242",
      holesky_dev_safe: "0x4242424242424242424242424242424242424242",
      hoodi_dev_safe: "0x00000000219ab540356cBB839Cbe05303d7705Fa",
      hoodi_devnet: "0x00000000219ab540356cBB839Cbe05303d7705Fa",
      hoodi_testnet: "0x00000000219ab540356cBB839Cbe05303d7705Fa", // https://github.com/eth-clients/hoodi
    },
    treasury: {
      default: 5,
      goerli_consensys: "0xAb07A64D407c25f02f1a2dc0aF97076630a03F17",
      goerli_dev_consensys: "0xAb07A64D407c25f02f1a2dc0aF97076630a03F17",
      goerli_uat_consensys: "0xAb07A64D407c25f02f1a2dc0aF97076630a03F17",
      goerli_consensys_dev: "0xAb07A64D407c25f02f1a2dc0aF97076630a03F17",
      holesky_dev_consensys: "0xe8e738c2F1C383aB8282EbE30579118EC9CE4534",
      holesky_uat_consensys: "0xe8e738c2F1C383aB8282EbE30579118EC9CE4534",
      hoodi_dev_consensys: "0xd23D393167e391e62d464CD5ef09e52Ed58BC889",
      hoodi_uat_consensys: "0xd23D393167e391e62d464CD5ef09e52Ed58BC889",
      goerli_vault: "0x73cC0AFEaAc1E6f2C08A7D4484bB5628062558CB",
      goerli_live: "0x5137B5540730d44326fBb237184425A9FB311DdF",
      mainnet_vault: "0x2C8C8e8022827a97388C6Ae9C22FF26EA2f02542",
      mainnet_live: "0xd3947210779c046D5ADCE2a6665d650450A56280",
      mainnet_enzyme: "0x1ad1fc9964c551f456238Dd88D6a38344B5319D7",
      mainnet_komainu: "0xCdB0570d55Ebe8c8d678e090F86fa73729EF8Fc7",
      mainnet_consensys: "0xb631dB8b5D95947025b77bFB44De32eFA8bc15Da",
      mainnet_safe: "0xF9beDA1d78916CC89D4B3F6beF092Dc1D302112b",
      mainnet_2_safe: "0xF9beDA1d78916CC89D4B3F6beF092Dc1D302112b",
      holesky_devnet: "0xb3eb29AC481FCFAFA7008A4acf04737c7d6733EA",
      holesky_testnet: "0xe6fe1936Fa8120e57c7Dee1733693B59b392672c",
      holesky_dev_safe: "0xdA53Ce2F763A3270638127CEA2826e32Cd3428e5",
      hoodi_dev_safe: "0xdA53Ce2F763A3270638127CEA2826e32Cd3428e5",
      hoodi_devnet: "0x0000012368C1dCe73224b936271D44F1dd7b8eA0",
      hoodi_testnet: "0x0000012368C1dCe73224b936271D44F1dd7b8eA0",
    },
  },
};

export default hhuc;
