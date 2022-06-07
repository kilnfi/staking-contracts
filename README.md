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

[Foundry](https://github.com/foundry-rs/foundry) is used to manage the contracts source code and tests.

# Commands

## Compile

All sources can be built by running `forge build`

## Tests

You can run all the test suite by running `forge test`. Increase verbosity with `forge test -vvv` to retrieve complete error stack traces.
To run only one test file, you can run `forge test -vvv --match-contract StakingContractTest` which is the name of the contract you can find in the `StakingContract.t.sol` test file.


# Components

![Components](./docs/components.svg)

Generate by running `yarn docs`

## [Staking Contract](./natspec/StakingContract.md)

The Staking Contract is the main input of the system. Node Operator pre-register batchs of validator keys. End users can send multiples of 32 ETH directly to the contract, and if enough keys are available the validator deposit(s) will occur. Stakers are also able to define Withdrawer accounts, an account that is allow to withdraw the funds and the collected fees. This allows them to not only specify a different address than the one they use for deposits but also to change this account in the future.

## [Withdraw Contract](./natspec/WithdrawContract.md)

This contract is an upgradeable stub contract that will handle all the validator withdrawals once the process is written in stone in the Ethereum specs.