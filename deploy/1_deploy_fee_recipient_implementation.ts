import {HardhatRuntimeEnvironment} from 'hardhat/types';
import {DeployFunction} from 'hardhat-deploy/types';
import { isDeployed } from '../ts_utils';

const func: DeployFunction = async function ({
	deployments,
	getNamedAccounts,
  }: HardhatRuntimeEnvironment) {
	const { deployer } = await getNamedAccounts();

	  await deployments.deploy("FeeRecipient", {
		from: deployer,
		log: true
	  });

};

func.skip = async function ({ deployments, network }: HardhatRuntimeEnvironment): Promise<boolean> {
	const shouldSkip = (await isDeployed("FeeRecipient", deployments)) || network.name.endsWith("_consensys");
	if (shouldSkip) {
	  console.log("Skipped");
	}
	return shouldSkip;
  };

export default func;