import {HardhatRuntimeEnvironment} from 'hardhat/types';
import {DeployFunction} from 'hardhat-deploy/types';
import { isDeployed } from '../ts_utils';

const func: DeployFunction = async function ({
	deployments,
	getNamedAccounts,
	network
  }: HardhatRuntimeEnvironment) {
	const { deployer } = await getNamedAccounts();

	await deployments.deploy("StakingContract_1.1_Implementation", {
		contract: "StakingContract",
		from: deployer,
		log: true,
	  });

};

func.skip = async function ({ deployments, network }: HardhatRuntimeEnvironment): Promise<boolean> {
	const shouldSkip = await isDeployed("StakingContract_1.1_Implementation", deployments) || network.name !== "mainnet_vault" || network.name.endsWith("_iofinnet") || network.name.endsWith("_consensys") || network.name.endsWith("_safe")
	if (shouldSkip) {
	  console.log("Skipped");
	}
	return shouldSkip;
  };

export default func;