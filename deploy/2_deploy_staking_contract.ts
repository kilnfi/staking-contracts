import {HardhatRuntimeEnvironment} from 'hardhat/types';
import {DeployFunction} from 'hardhat-deploy/types';

const func: DeployFunction = async function ({
	deployments,
	getNamedAccounts,
	ethers,
	artifacts,
  }: HardhatRuntimeEnvironment) {
	const { deployer, proxyAdmin, operator, admin, depositContract } = await getNamedAccounts();

	const withdrawDeployment = await deployments.get("WithdrawContract");
	const WithdrawContract = await ethers.getContractAt("WithdrawContract", withdrawDeployment.address);
	const withdrawalCredentials = await WithdrawContract.getWithdrawalCredentials();

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
			operator,
			admin,
			depositContract,
			withdrawalCredentials
				  ]
			  }
		  }
		},
	  });

};

export default func;