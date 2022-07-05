import {HardhatRuntimeEnvironment} from 'hardhat/types';
import {DeployFunction} from 'hardhat-deploy/types';

const func: DeployFunction = async function ({
	deployments,
	getNamedAccounts,
  }: HardhatRuntimeEnvironment) {
	const { deployer, admin } = await getNamedAccounts();

	await deployments.deploy("Treasury", {
		from: deployer,
		log: true,
		args: [
			admin
		]
	  });

};

export default func;