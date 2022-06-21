import {HardhatRuntimeEnvironment} from 'hardhat/types';
import {DeployFunction} from 'hardhat-deploy/types';

const func: DeployFunction = async function ({
	deployments,
	getNamedAccounts,
  }: HardhatRuntimeEnvironment) {
	const { deployer, proxyAdmin } = await getNamedAccounts();

	await deployments.deploy("ExecutionLayerFeeRecipient", {
		from: deployer,
		log: true,
		args: [1],
		proxy: {
		  owner: proxyAdmin,
		  proxyContract: "TUPProxy",
		  execute: {
			  init: {
				  methodName: 'initELFR',
				  args: [
					"0x0000000000000000000000000000000000000000",
					"0x0000000000000000000000000000000000000000000000000000000000000000"
				  ]
			  }
		  }
		},
	  });

};

export default func;