import {HardhatRuntimeEnvironment} from 'hardhat/types';
import {DeployFunction} from 'hardhat-deploy/types';

const func: DeployFunction = async function ({
	deployments,
	getNamedAccounts,
  }: HardhatRuntimeEnvironment) {
	const { deployer, proxyAdmin, operator, admin, depositContract } = await getNamedAccounts();

	  await deployments.deploy("ConsensusLayerFeeRecipient", {
		from: deployer,
		log: true,
		args: [1],
		proxy: {
		  owner: proxyAdmin,
		  proxyContract: "TUPProxy",
		  execute: {
			  init: {
				  methodName: 'initCLFR',
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