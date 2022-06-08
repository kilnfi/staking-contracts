# 🥩
![format](https://github.com/skillz-blockchain/staking-contracts/actions/workflows/Format.yaml/badge.svg)
![lint](https://github.com/skillz-blockchain/staking-contracts/actions/workflows/Lint.yaml/badge.svg)
![mythril](https://github.com/skillz-blockchain/staking-contracts/actions/workflows/Mythril.yaml/badge.svg)
![Tests](https://github.com/skillz-blockchain/staking-contracts/actions/workflows/Tests.yaml/badge.svg)

# Summary

The Staking Contracts allows the registered node operators to deposit validator keys that are funded by external users. This allows a seemless staking experience for end users, enabling them to stake one or several validators with one transaction.

# Dependencies

## Node Modules

Install all required Node dependencies by running `yarn`

## Foundry

[Foundry](https://github.com/foundry-rs/foundry) is used to manage the contracts source code and tests. Install it by following the instructions and make sure that `forge` and `cast` are available commands.

# Commands

## Compile

All sources can be built by running `forge build`

## Tests

You can run all the test suite by running `forge test`. Increase verbosity with `forge test -vvv` to retrieve complete error stack traces.
To run only one test file, you can run `forge test -vvv --match-contract StakingContractTest` which is the name of the contract you can find in the `StakingContract.t.sol` test file.

# Deployment

You will find all the steps to properly deploy and populate the system. You will find several `VARIABLES` that you will need to make sure are properly setup according to the instructions. They will be referenced by using the `$VARIABLE` syntax in the required commands.

## I. Pre-Deployment Steps

### Prepare System Administrator (`SYSTEM_ADMIN`)

The system administrator address will be in charge of all the admin operations in the all the system, like changing the administrator or the operator address.

#### Gnosis Safe

If you want to share the administration between several recipients, you can deploy a Gnosis Safe contract and configure its threshold as you please. The easiest way to deploy a Gnosis Safe is to use the official [Gnosis Safe App](https://gnosis-safe.io/app) and follow the instructions to setup the initial members and threshold.

### Prepare Implementation Administrator (`IMPLEMENTATION_ADMIN`)

The system is composed of several upgradeable contracts. These contracts work by using a proxy that is following the transparent proxy pattern. This simply means that the administrator of the proxies cannot call functions on the system like a regular wallet and is bound to the proxy methods. This is useful when you want to make sure there are no collisions between method names in the proxy and in the implementation. The Implementation Administrator is the account in charge to orchestrating implementation upgrades.

#### Gnosis Safe

If you want to share the implementation administration between several recipients, you can deploy a Gnosis Safe contract and configure its threshold as you please. The easiest way to deploy a Gnosis Safe is to use the official [Gnosis Safe App](https://gnosis-safe.io/app) and follow the instructions to setup the initial members and threshold.

This is not the same gnosis safe account as the system administrator, it needs to have a different address.

### Prepare Operator (`OPERATOR`)

This account will be in charge of adding keys to the system. It has to be handled by the Node Operator that manages the validator infrastructure.

## II. Deployment Steps

### Deployment Variables

These environment variables are required for the deployment command.

#### Deploying Accounts (`MNEMONIC`)

You will need a mnemonic phrase pointing to a funded account on the deployment network. This account won't have any ownership or extra rights upon the system, losing this key will no represent a threat for the system (still, don't lose your keys)

#### Ethereum RPC Endpoint (`RPC_URL`)

You will need an RPC endpoint on the deployment network. You can use a service like Infura, Alchemy or your own node.

#### Network (`NETWORK`)

The name of the network you are deploying to. Can be one of:
- `goerli`

#### Deposit Contract (`DEPOSIT_CONTRACT`)

You will need to have the address of the official Deposit Contract available on your deployment network.

### Configuration Variables

These configuration variables are required to be properly set for the deployment. The variable naming is `file:path = value`

- `hardhat.config.ts`:`namedAccounts.admin.$NETWORK` = `$SYSTEM_ADMIN`
- `hardhat.config.ts`:`namedAccounts.proxyAdmin.$NETWORK` = `$PROXY_ADMIN`
- `hardhat.config.ts`:`namedAccounts.operator.$NETWORK` = `$OPERATOR`
- `hardhat.config.ts`:`namedAccounts.depositContract.$NETWORK` = `$DEPOSIT_CONTRACT`

### Deployment Command

To start the deployment process, run this command by replacing the variables with the values gathered in the steps above and making sure that configuration file values are set properly.

`env MNEMONIC=$MNEMONIC RPC_URL=$RPC_URL yarn hh deploy --network $NETWORK`

## III. Post Deployment Steps

### Add Validator Keys (Testnet only)

This method is intended for testnet only purposes. In production, it is expected from the operator to properly submit keys from its infrastructure and making sure the operator wallet is stored in the adequate hardware or service. This solution is mainly meant to quickly populate the contract.

You will need to prepare the following variable before sending the call

- `PUBLIC_KEYS`: Concatenate your public keys.
- `SIGNATURES`: Concatenate your signatures. Make sure the signature for a public key is at the same index in the concatenation as its associated public key.
- `KEY_COUNT`: Total count of keys
- `STAKING_CONTRACT_ADDRESS`: Address of the deployed staking contract
- `RPC_URL`: Ethereum RPC endpoint on the deployment network
- `MNEMONIC_FILE`: A file containing the operator mnemonic key

Run

`cast send --mnemonic-path $MNEMONIC_FILE $STAKING_CONTRACT_ADDRESS "registerValidators(uint256,bytes,bytes)" $KEY_COUNT $PUBLIC_KEYS $SIGNATURES`

# Upgrade

The upgrade process consists in deploying a new implementation contract and changing the implementation pointed by the corresponding Proxy. In production, this upgrade will be proposed as a multisig signature and all involved parties will be able to see what is the new implementation address for the target proxy.

## Upgrade method

To upgrade a proxy, you can call `upgradeTo(address)` or `upgradeToAndCall(address,bytes)` with the implementation admin multisig.

## Upgrade checksum

To make sure the upgrade is actually pointing to a contract implementation of a smart contract code that all parties have agreed upon, we can reproduce these steps locally.

### I. Getting implementation bytecode

To retrieve the implementation bytecode, you have to compile the contracts locally. In the following example, we assume that the upgrade is for the `StakingContract` contract.

To compile everything, run `forge build`
To retrieve the bytecode, run `cat out/StakingContract.sol/StakingContract.json | jq .deployedBytecode.object`

### II. Getting live bytecode

To retrieve the implementation bytecode that is currently deployed on the network, you will need:

- `RPC_URL`: Ethereum RPC endpoint on the deployment network
- `IMPLEMENTATION_ADDRESS`: Address of the new implementation address

and you can run `cast code --rpc-url $RPC_URL $IMPLEMENTATION_ADDRESS`

You can then compare if the local bytecode and the deployed bytecode are matching.

# Components

![Components](./docs/components.svg)

Generate by running `yarn docs`

## [Staking Contract](./natspec/StakingContract.md)

The Staking Contract is the main input of the system. Node Operator pre-register batchs of validator keys. End users can send multiples of 32 ETH directly to the contract, and if enough keys are available the validator deposit(s) will occur. Stakers are also able to define Withdrawer accounts, an account that is allow to withdraw the funds and the collected fees. This allows them to not only specify a different address than the one they use for deposits but also to change this account in the future.

## [Withdraw Contract](./natspec/WithdrawContract.md)

This contract is an upgradeable stub contract that will handle all the validator withdrawals once the process is written in stone in the Ethereum specs.