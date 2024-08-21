import { getContractAddress } from "ethers/lib/utils";
import { DeployFunction } from "hardhat-deploy/types";
import { HardhatRuntimeEnvironment } from "hardhat/types";
import { isDeployed } from "../ts_utils/index";

const getMaxFeeBps = (network: string): number => {
  switch (network) {
    case "holesky_dev_safe":
      return 1000;
    case "mainnet_safe":
      return 1000; //10% max user fee

    default:
      return 1000;
  }
};

const getMaxOperatorFeeBps = (network: string): number => {
  switch (network) {
    case "holesky_dev_safe":
      return 10000;
    case "mainnet_safe":
      return 10000; // Leave the possibility of doing the split onchain in the future
    
    default:
      return 0;
  }
};

const getFeeBps = (network: string): number => {
  switch (network) {
    case "holesky_dev_safe":
      return 600;
    case "mainnet_safe":
      return 600; //6% end-user fee
    
    default:
      return 600;
  }
};

const getOperatorFeeBps = (network: string): number => {
  switch (network) {
    case "holesky_dev_safe":
      return 0;
    case "mainnet_safe":
      return 0; // at the start all the fees go to the treasury
    
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
  const { deployer, admin, depositContract, treasury } = await getNamedAccounts();
  
  //1. Deploy Minimal Recipient
  const feeRecipientDeployment = await deployments.deploy("FeeRecipient", {
    from: deployer,
		log: true
  });
  
  //2. Compute future staking contract address
  const signer = await ethers.getSigner(deployer);
  const txCount = await signer.getTransactionCount();
  const futureStakingContractAddress = getContractAddress({
    from: deployer,
    nonce: txCount + 4, // staking contract proxy is in 5 txs
  });

  //3. Deploy ConsensusLayerFeeDispatcher without proxy
  const clfdDeployment = (await deployments.deploy("ConsensusLayerFeeDispatcher", {
    from: deployer,
    log: true,
    args: [0],
  }));


  const clf = await ethers.getContractAt("ConsensusLayerFeeDispatcher", clfdDeployment.address);
  await (await clf.initCLD(futureStakingContractAddress)).wait();

  //4. Deploy ExecutionLayerFeeDispatcher without proxy
  const elfdDeployment = await deployments.deploy("ExecutionLayerFeeDispatcher", {
    from: deployer,
    log: true,
    args: [0],
  });

  const elf = await ethers.getContractAt("ExecutionLayerFeeDispatcher", elfdDeployment.address);
  await (await elf.initELD(futureStakingContractAddress)).wait();


  //5. Deploy StakingContract without proxy
  const stakingContractDeployment = await deployments.deploy("StakingContract", {
    from: deployer,
    log: true,
  });

  const stakingContract = await ethers.getContractAt("StakingContract", stakingContractDeployment.address);

  const initStaking_1 = await stakingContract.initialize_1(
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
  );
  await initStaking_1.wait();

  if (stakingContractDeployment.address.toLowerCase() !== futureStakingContractAddress.toLowerCase()) {
    throw new Error("Invalid future deployment address for staking contract");
  }
};

func.skip = async function ({ deployments, network }: HardhatRuntimeEnvironment): Promise<boolean> {
  const shouldSkip = network.name !== "holesky_dev_safe" && network.name !== "mainnet_safe";
  if (shouldSkip) {
    console.log("Skipped");
  }
  return shouldSkip;
};

export default func;
