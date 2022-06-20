import { HardhatUserConfig } from "hardhat/types";
import '@nomiclabs/hardhat-ethers';
import "hardhat-deploy";
import '@primitivefi/hardhat-dodoc';

/**
 * @type import('hardhat/config').HardhatUserConfig
 */
const hhuc: HardhatUserConfig = {
  solidity: "0.8.13",
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
  },
  dodoc: {
    include: [
      "StakingContract",
      "ExecutionLayerFeeRecipient",
      "ConsensusLayerFeeRecipient"
    ],
    outputDir: 'natspec'
  },
  namedAccounts: {
    deployer: {
      default: 0
    },
    proxyAdmin: {
      default: 1,
      goerli: '0x3B9B2C07eff60aC828117C997E04c61890Ad2Ed7'
    },
    admin: {
      default: 2,
      goerli: '0xC4b8469165d0A0e0939500BdeCE7c0CD3415a9fb'
    },
    depositContract: {
      default: 4,
      goerli: "0xff50ed3d0ec03ac01d4c79aad74928bff48a7b2b",
    },
  },
};

export default hhuc;
