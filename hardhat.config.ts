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
        runs: 10000,
      }
    }
  },
  paths: {
    sources: "./src/contracts",
  },
  networks: {
    goerli_vault: {
      url: process.env.RPC_URL || "",
      accounts: {
        mnemonic: process.env.MNEMONIC || "",
      },
    },
    goerli_live: {
      url: process.env.RPC_URL || "",
      accounts: {
        mnemonic: process.env.MNEMONIC || "",
      },
    },
    mainnet_vault: {
      url: process.env.RPC_URL || "",
      accounts: {
        mnemonic: process.env.MNEMONIC || "",
      },
    },
    mainnet_live: {
      url: process.env.RPC_URL || "",
      accounts: {
        mnemonic: process.env.MNEMONIC || "",
      },
    },
    mainnet_enzyme: {
      url: process.env.RPC_URL || "",
      accounts: {
        mnemonic: process.env.MNEMONIC || "",
      },
    },
    mainnet_komainu: {
      url: process.env.RPC_URL || "",
      accounts: {
        mnemonic: process.env.MNEMONIC || "",
      },
    }
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
      goerli_vault: "0x3B9B2C07eff60aC828117C997E04c61890Ad2Ed7",
      goerli_live: "0x3B9B2C07eff60aC828117C997E04c61890Ad2Ed7",
      mainnet_vault: "0x3c69D70ea8487a7E64127a6Eae194ada4C144318",
      mainnet_live: "0xd235d4Eb3A483743C506C8AB6ee50f4eBfDEF4D8",
      mainnet_enzyme: "0xb270FE91e8E4b80452fBF1b4704208792A350f53",
      mainnet_komainu: "0xd235d4Eb3A483743C506C8AB6ee50f4eBfDEF4D8"
    },
    admin: {
      default: 2,
      goerli_vault: "0xC4b8469165d0A0e0939500BdeCE7c0CD3415a9fb",
      goerli_live: "0xC4b8469165d0A0e0939500BdeCE7c0CD3415a9fb",
      mainnet_vault: "0xD3269B4daBd8AA336155F741C534CBAC87526A8E",
      mainnet_live: "0xCf53Ef5be9C713585D2fEF40e72D9c7C4fE1D5F2",
      mainnet_enzyme: "0x45DAD754897ef0b2780349AD7c7000c72717b24E",
      mainnet_komainu: "0xCf53Ef5be9C713585D2fEF40e72D9c7C4fE1D5F2"
    },
    depositContract: {
      default: 4,
      goerli_vault: "0xff50ed3d0ec03ac01d4c79aad74928bff48a7b2b",
      goerli_live: "0xff50ed3d0ec03ac01d4c79aad74928bff48a7b2b",
      mainnet_vault: "0x00000000219ab540356cBB839Cbe05303d7705Fa",
      mainnet_live: "0x00000000219ab540356cBB839Cbe05303d7705Fa",
      mainnet_enzyme: "0x00000000219ab540356cBB839Cbe05303d7705Fa",
      mainnet_komainu: "0x00000000219ab540356cBB839Cbe05303d7705Fa"
    },
    treasury: {
      default: 5,
      goerli_vault: "0x73cC0AFEaAc1E6f2C08A7D4484bB5628062558CB",
      goerli_live: "0x5137B5540730d44326fBb237184425A9FB311DdF",
      mainnet_vault: "0x2C8C8e8022827a97388C6Ae9C22FF26EA2f02542",
      mainnet_live: "0xd3947210779c046D5ADCE2a6665d650450A56280",
      mainnet_enzyme: "0x1ad1fc9964c551f456238Dd88D6a38344B5319D7",
      mainnet_komainu: "0xCdB0570d55Ebe8c8d678e090F86fa73729EF8Fc7"
    },
  },
};

export default hhuc;
