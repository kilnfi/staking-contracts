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
    goerli: {
      url: process.env.RPC_URL || "",
      accounts: {
        mnemonic: process.env.MNEMONIC || "",
      },
    },
    ropsten: {
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
      goerli: "0x3B9B2C07eff60aC828117C997E04c61890Ad2Ed7",
      ropsten: "0xD53992E36090ca80C14197C09475fe09909CaeB1",
    },
    admin: {
      default: 2,
      goerli: "0xC4b8469165d0A0e0939500BdeCE7c0CD3415a9fb",
      ropsten: "0x8039f91Ce95F9DE56ab607a20fD27830Ab3A5813",
    },
    depositContract: {
      default: 4,
      goerli: "0xff50ed3d0ec03ac01d4c79aad74928bff48a7b2b",
      ropsten: "0x6f22fFbC56eFF051aECF839396DD1eD9aD6BBA9D",
    },
    ledger: {
      default: 5,
      goerli: "0xd13E4bF0d8b793e00977aC7Cf19800faC7A97fc8",
      ropsten: "0xd13E4bF0d8b793e00977aC7Cf19800faC7A97fc8",
    },
    kiln: {
      default: 6,
      goerli: "0x5137B5540730d44326fBb237184425A9FB311DdF",
      ropsten: "0x5137B5540730d44326fBb237184425A9FB311DdF",
    }
  },
};

export default hhuc;
