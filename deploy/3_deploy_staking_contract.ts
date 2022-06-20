import {HardhatRuntimeEnvironment} from 'hardhat/types';
import {DeployFunction} from 'hardhat-deploy/types';

const func: DeployFunction = async function ({
	deployments,
	getNamedAccounts,
  }: HardhatRuntimeEnvironment) {
	const { deployer, proxyAdmin, operator, admin, depositContract } = await getNamedAccounts();

	const elfrDeployment = await deployments.get("ExecutionLayerFeeRecipient");
	const clfrDeployment = await deployments.get("ConsensusLayerFeeRecipient");

	await deployments.deploy("StakingContract", {
		from: deployer,
		log: true,
		proxy: {
		  owner: proxyAdmin,
		  proxyContract: "TUPProxy",
		  execute: {
			  init: {
				  methodName: 'initialize_1',
				  args: [
			admin,
			depositContract,
			elfrDeployment.address,
			clfrDeployment.address,
			500,
			500
				  ]
			  }
		  }
		},
	  });

};

export default func;