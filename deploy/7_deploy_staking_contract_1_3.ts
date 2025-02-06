import {HardhatRuntimeEnvironment} from 'hardhat/types';
import {DeployFunction} from 'hardhat-deploy/types';
import { isDeployed } from '../ts_utils';

const func: DeployFunction = async function ({
	deployments,
	getNamedAccounts,
	network
  }: HardhatRuntimeEnvironment) {
	const { deployer } = await getNamedAccounts();

	await deployments.deploy("StakingContract_1.3_Implementation", {
		contract: "StakingContract",
		from: deployer,
		log: true,
	  });

};

func.skip = async function ({ deployments, network }: HardhatRuntimeEnvironment): Promise<boolean> {
	const shouldSkip = await isDeployed("StakingContract_1.3_Implementation", deployments) || network.name !== "mainnet_live"
	if (shouldSkip) {
	  console.log("Skipped");
	}
	return shouldSkip;
  };

export default func;