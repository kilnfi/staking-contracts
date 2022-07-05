import {HardhatRuntimeEnvironment} from 'hardhat/types';
import {DeployFunction} from 'hardhat-deploy/types';

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

export default func;