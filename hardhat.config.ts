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
        runs: 200,
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
      mainnet_vault: "0x3c69D70ea8487a7E64127a6Eae194ada4C144318"
    },
    admin: {
      default: 2,
      goerli_vault: "0xC4b8469165d0A0e0939500BdeCE7c0CD3415a9fb",
      goerli_live: "0xC4b8469165d0A0e0939500BdeCE7c0CD3415a9fb",
      mainnet_vault: "0xD3269B4daBd8AA336155F741C534CBAC87526A8E"
    },
    depositContract: {
      default: 4,
      goerli_vault: "0xff50ed3d0ec03ac01d4c79aad74928bff48a7b2b",
      goerli_live: "0xff50ed3d0ec03ac01d4c79aad74928bff48a7b2b",
      mainnet_vault: "0x00000000219ab540356cBB839Cbe05303d7705Fa"
    },
    treasury: {
      default: 5,
      goerli_vault: "0x73cC0AFEaAc1E6f2C08A7D4484bB5628062558CB",
      goerli_live: "0x5137B5540730d44326fBb237184425A9FB311DdF",
      mainnet_vault: "0x2C8C8e8022827a97388C6Ae9C22FF26EA2f02542"
    }
  },
};

export default hhuc;
