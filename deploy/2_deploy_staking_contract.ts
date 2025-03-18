import { getContractAddress } from "ethers/lib/utils";
import { DeployFunction } from "hardhat-deploy/types";
import { HardhatRuntimeEnvironment } from "hardhat/types";
import { isDeployed } from "../ts_utils/index";

const getMaxFeeBps = (network: string): number => {
  switch (network) {
    case "goerli_consensys":
      return 5000;
    case "goerli_consensys_dev":
      return 5000;
    case "goerli_vault":
      return 5000;
    case "goerli_live":
      return 5000;
    case "hoodi_devnet":
      return 5000;
    case "hoodi_testnet":
      return 5000;
    case "mainnet_vault":
      return 5000;
    case "mainnet_live":
      return 5000;
    case "mainnet_enzyme":
      return 5000;
    case "mainnet_komainu":
      return 5000;
    default:
      return 5000;
  }
};

const getMaxOperatorFeeBps = (network: string): number => {
  switch (network) {
    case "goerli_consensys":
      return 5000;
    case "goerli_consensys_dev":
      return 5000;
    case "goerli_vault":
      return 5000;
    case "goerli_live":
      return 5000;
    case "hoodi_devnet":
      return 5000;
    case "hoodi_testnet":
      return 5000;
    case "mainnet_vault":
      return 5000;
    case "mainnet_live":
      return 5000;
    case "mainnet_enzyme":
      return 5000;
    case "mainnet_komainu":
      return 5000;
    default:
      return 5000;
  }
};

const getFeeBps = (network: string): number => {
  switch (network) {
    case "goerli_consensys":
      return 500;
    case "goerli_consensys_dev":
      return 500;
    case "goerli_vault":
      return 700;
    case "goerli_live":
      return 700;
    case "hoodi_devnet":
      return 700;
    case "hoodi_testnet":
      return 700;
    case "mainnet_vault":
      return 700;
    case "mainnet_live":
      return 800;
    case "mainnet_enzyme":
      return 400;
    case "mainnet_komainu":
      return 400;
    default:
      return 700;
  }
};

const getOperatorFeeBps = (network: string): number => {
  switch (network) {
    case "goerli_consensys":
      return 500;
    case "goerli_consensys_dev":
      return 500;
    case "goerli_vault":
      return 0;
    case "goerli_live":
      return 0;
    case "mainnet_vault":
      return 0;
    case "mainnet_live":
      return 0;
    case "mainnet_enzyme":
      return 400;
    case "mainnet_komainu":
      return 0;
    default:
      return 0;
  }
};

const func: DeployFunction = async function ({
  deployments,
  getNamedAccounts,
  ethers,
  network,
}: HardhatRuntimeEnvironment) {
  const { deployer, proxyAdmin, admin, depositContract, treasury } = await getNamedAccounts();

  const feeRecipientDeployment = await deployments.get("FeeRecipient");

  const signer = await ethers.getSigner(deployer);
  const txCount = await signer.getTransactionCount();
  const futureStakingContractAddress = getContractAddress({
    from: deployer,
    nonce: txCount + 5, // staking contract proxy is in 6 txs
  });

  const clfdDeployment = await deployments.deploy("ConsensusLayerFeeDispatcher", {
    from: deployer,
    log: true,
    args: [1],
    proxy: {
      owner: proxyAdmin,
      proxyContract: "TUPProxy",
      execute: {
        init: {
          methodName: "initCLD",
          args: [futureStakingContractAddress],
        },
      },
    },
  });

  const elfdDeployment = await deployments.deploy("ExecutionLayerFeeDispatcher", {
    from: deployer,
    log: true,
    args: [1],
    proxy: {
      owner: proxyAdmin,
      proxyContract: "TUPProxy",
      execute: {
        init: {
          methodName: "initELD",
          args: [futureStakingContractAddress],
        },
      },
    },
  });

  const stakingContractDeployment = await deployments.deploy("StakingContract", {
    from: deployer,
    log: true,
    proxy: {
      owner: proxyAdmin,
      proxyContract: "TUPProxy",
      execute: {
        init: {
          methodName: "initialize_1",
          args: [
            admin,
            treasury,
            depositContract,
            elfdDeployment.address,
            clfdDeployment.address,
            feeRecipientDeployment.address,
            getFeeBps(network.name),
            getOperatorFeeBps(network.name),
            getMaxFeeBps(network.name),
            getMaxOperatorFeeBps(network.name),
          ],
        },
      },
    },
  });

  if (stakingContractDeployment.address.toLowerCase() !== futureStakingContractAddress.toLowerCase()) {
    throw new Error("Invalid future deployment address for staking contract");
  }
};

func.skip = async function ({ deployments, network }: HardhatRuntimeEnvironment): Promise<boolean> {
  const shouldSkip =
    ((await isDeployed("ConsensusLayerFeeDispatcher_Proxy", deployments)) &&
    (await isDeployed("ExecutionLayerFeeDispatcher_Proxy", deployments)) &&
    (await isDeployed("StakingContract_Proxy", deployments))) || network.name.endsWith("_consensys")  || network.name.endsWith("_safe");
  if (shouldSkip) {
    console.log("Skipped");
  }
  return shouldSkip;
};

export default func;
