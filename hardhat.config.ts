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
  },
  dodoc: {
    include: [
      "StakingContract",
      "MinimalReceiver"
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
    },
    admin: {
      default: 2,
      goerli_vault: "0xC4b8469165d0A0e0939500BdeCE7c0CD3415a9fb",
    },
    depositContract: {
      default: 4,
      goerli_vault: "0xff50ed3d0ec03ac01d4c79aad74928bff48a7b2b",
    },
    treasury: {
      default: 5,
      goerli_vault: "0x73cC0AFEaAc1E6f2C08A7D4484bB5628062558CB"
    }
  },
};

export default hhuc;
