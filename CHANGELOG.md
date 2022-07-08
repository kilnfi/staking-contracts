# Staking Contracts changelog

## v0.2.0 (July 8th 2022)

### :dizzy: Features

- Add new `deposit()` method that works like the `receive()` fallback
- Add new `Treasury` contract and rework fee dispatching
- 
### Bug Fixes

- Ensure fee recipients work by preventing `DELEGATECALL` -> `DELEGATECALL`, introduces new unupgradeable `FeeRecipient` and `ExecutionLayerFeeDispatcher` + `ConsensusLayerFeeDispatcher` upgradeable contracts

## v0.1.0 (June 21th 2022)

### :dizzy: Features

- Add `StakingContract` contract that registers operators, validators keys and allows users to deposit batches of 32 ETH into the deposited validator keys
- Add `ExecutionLayerFeeRecipient` contract that handles all the fees collected on the execution layer for each validator key
- Add `ConsensusLayerFeeRecipient` contract that handles all the fees collected on the consensus layer for each validator key
- Add `TUPProxy` to manage the upgradeable contracts and allow admins to pause the entire contract if needed

### 🕹️ Others

- Add doc generation with `yarn doc`
- Add ci job to run smart contract tests
- Add ci job to run smart contract linting
- Add ci job to run smart contract static analysis with Mythril
- Add ci job to run smart contract formatting checks