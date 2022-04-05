import {HardhatRuntimeEnvironment} from 'hardhat/types';
import {DeployFunction} from 'hardhat-deploy/types';

const func: DeployFunction = async function ({
	deployments,
	getNamedAccounts,
	ethers,
	artifacts,
  }: HardhatRuntimeEnvironment) {
	const { deployer, proxyAdmin } = await getNamedAccounts();
	await deployments.deploy("WithdrawContract", {
		from: deployer,
		log: true,
		proxy: {
		  owner: proxyAdmin,
		  proxyContract: "TUPProxy",
		},
	  });
};

export default func;