# Staking Contracts changelog

## v0.2.1 (August 26th 2022)

### :dizzy: Features

- Add new deployment digest generator (`deployment.*.json`)
- [Add `treasury` setter](https://github.com/kilnfi/staking-contracts/pull/48)
  
### Bug Fixes

- [Fix audit finding `HAL-01 - REWARDS WITHDRAWAL WITHOUT FEES CHARGING IS POSSIBLE`](https://github.com/kilnfi/staking-contracts/pull/55)
- [Fix audit finding `HAL-02 - OPERATORS FAVORING DUE TO INCORRECT USE OF BLOCKHASH`](https://github.com/kilnfi/staking-contracts/pull/53)
- [Fix audit finding `HAL-03 - ADDING VAST NUMBER OF OPERATORS CAN DOS DEPOSIT FUNCTIONALITY`](https://github.com/kilnfi/staking-contracts/pull/50)
- [Fix audit finding `HAL-04 - LACK OF TRANSFER-OWNERSHIP PATTERN`](https://github.com/kilnfi/staking-contracts/pull/54)
- [Fix audit finding `HAL-05 - STAKINGCONTRACT LACKS FEES VALIDATION IN INITIALIZE FUNCTION`](https://github.com/kilnfi/staking-contracts/pull/52)
- [Fix audit finding `HAL-06 - UNUSED ERROR AND FUNCTIONS DECLARED`](https://github.com/kilnfi/staking-contracts/pull/56)
- [Fix audit finding `HAL-08 - LIMIT INCREASE FOR DEACTIVATED OPERATOR IS POSSIBLE`](https://github.com/kilnfi/staking-contracts/pull/49)
- [Remove unused `deposit(address)` method](https://github.com/kilnfi/staking-contracts/pull/57)

## v0.2.0 (July 8th 2022)

### :dizzy: Features

- Add new `deposit()` method that works like the `receive()` fallback
- Add new `Treasury` contract and rework fee dispatching

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