import { DeploymentsExtension } from "hardhat-deploy/dist/types";


export const isDeployed = async (
  name: string,
  deployments: DeploymentsExtension
): Promise<boolean> => {
  try {
    const checkedDeployment = await deployments.get(name);
    return checkedDeployment.receipt?.status === 1;
  } catch (e) {
    return false;
  }
};