import {HardhatRuntimeEnvironment} from 'hardhat/types';
import {DeployFunction} from 'hardhat-deploy/types';
import { getContractAddress } from "ethers/lib/utils";


const func: DeployFunction = async function ({
	deployments,
	getNamedAccounts,
	ethers,
  }: HardhatRuntimeEnvironment) {
	const { deployer, proxyAdmin, admin, depositContract, treasury } = await getNamedAccounts();

	const feeRecipientDeployment = await deployments.get("FeeRecipient");

	const signer = await ethers.getSigner(deployer);
	const txCount = await signer.getTransactionCount();
	const futureStakingContractAddress = getContractAddress({
		from: deployer,
		nonce: txCount + 5, // staking contract proxy is in 6 txs
	  });

	const clfdDeployment = await deployments.deploy("ConsensusLayerFeeDispatcher", {
		from: deployer,
		log: true,
		args: [1],
		proxy: {
		  owner: proxyAdmin,
		  proxyContract: "TUPProxy",
		  execute: {
			  init: {
				  methodName: 'initCLD',
				  args: [
					futureStakingContractAddress
				  ]
			  }
		  }
		},
	  });

	  const elfdDeployment = await deployments.deploy("ExecutionLayerFeeDispatcher", {
		from: deployer,
		log: true,
		args: [1],
		proxy: {
		  owner: proxyAdmin,
		  proxyContract: "TUPProxy",
		  execute: {
			  init: {
				  methodName: 'initELD',
				  args: [
					futureStakingContractAddress
				  ]
			  }
		  }
		},
	  });

	const stakingContractDeployment = await deployments.deploy("StakingContract", {
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
			treasury,
			depositContract,
			elfdDeployment.address,
			clfdDeployment.address,
			feeRecipientDeployment.address,
			700,
			0	
				  ]
			  }
		  }
		},
	  });

	  if (stakingContractDeployment.address.toLowerCase() !== futureStakingContractAddress.toLowerCase()) {
		throw new Error("Invalid future deployment address for staking contract")
	  }

};

export default func;