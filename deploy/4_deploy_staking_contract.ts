import {HardhatRuntimeEnvironment} from 'hardhat/types';
import {DeployFunction} from 'hardhat-deploy/types';

const func: DeployFunction = async function ({
	deployments,
	getNamedAccounts,
  }: HardhatRuntimeEnvironment) {
	const { deployer, proxyAdmin, admin, depositContract } = await getNamedAccounts();

	const elfrDeployment = await deployments.get("ExecutionLayerFeeRecipient");
	const clfrDeployment = await deployments.get("ConsensusLayerFeeRecipient");
	const treasuryDeployment = await deployments.get("Treasury");

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
			treasuryDeployment.address,
			depositContract,
			elfrDeployment.address,
			clfrDeployment.address,
			200,
			200,
			800
				  ]
			  }
		  }
		},
	  });

};

export default func;