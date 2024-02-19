import {HardhatRuntimeEnvironment} from 'hardhat/types';
import {DeployFunction} from 'hardhat-deploy/types';
import { isDeployed } from '../ts_utils';

const func: DeployFunction = async function ({
	deployments,
	getNamedAccounts,
	network
  }: HardhatRuntimeEnvironment) {
	const { deployer } = await getNamedAccounts();

	await deployments.deploy("StakingContract_1.2_Implementation", {
		contract: "StakingContract",
		from: deployer,
		log: true,
	  });

	await deployments.deploy("ConsensusLayerFeeDispatcher_1.2_Implementation", {
		contract: "ConsensusLayerFeeDispatcher",
		from: deployer,
		log: true,
		args: [2],
	});
};

func.skip = async function ({ deployments, network }: HardhatRuntimeEnvironment): Promise<boolean> {
	const shouldSkip = (await isDeployed("StakingContract_1.2_Implementation", deployments) && await isDeployed("ConsensusLayerFeeDispatcher_1.2_Implementation", deployments)) || network.name.endsWith("_consensys");
	if (shouldSkip) {
	  console.log("Skipped");
	}
	return shouldSkip;
  };

export default func;