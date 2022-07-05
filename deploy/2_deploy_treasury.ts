import {HardhatRuntimeEnvironment} from 'hardhat/types';
import {DeployFunction} from 'hardhat-deploy/types';

const func: DeployFunction = async function ({
	deployments,
	getNamedAccounts,
  }: HardhatRuntimeEnvironment) {
	const { deployer, admin, ledger, kiln } = await getNamedAccounts();

	await deployments.deploy("Treasury", {
		from: deployer,
		log: true,
		args: [
			admin,
			[
				ledger,
				kiln,
			],
			[
				8750,
				1250,
			]
		]
	  });

};

export default func;