# Staking Contracts changelog


## [latest](https://github.com/kilnfi/staking-contracts)

- [feat: add optional OFAC sanctions check](https://github.com/kilnfi/staking-contracts/pull/101/commits/4513c1e406c8dffe126bc450dfc02af510187933)
- [feat: blockList](https://github.com/kilnfi/staking-contracts/pull/101/commits/b680e4e017dfb57a4c97425f1ee85c118fd95e53)
- [refacto: refresh tests]()

## [1.2.0](https://github.com/kilnfi/staking-contracts/releases/tag/1.2.0)

This entry was created retroactively and is not exhaustive, the git history is fairly detailed and can be used to track minor changes not logged here (tests changes, gas opti, minor fixes). The history is best viewed on github to see the matching issues.

- [feat: implementation of batch withdrawal functions](https://github.com/kilnfi/staking-contracts/commit/eaaff6975dccb641b93e049f072c957a99854754)
- [feat: implementation of CL fee dispatching](https://github.com/kilnfi/staking-contracts/commit/8a2a7e0b61874b71e7d036e16425ec4e9bcf3835)
- [feat: requestValidatorExit()](https://github.com/kilnfi/staking-contracts/commit/757f17d8e187031332a2357427cfdc0a6de7717e)
- [feat: new CL dispatch logic](https://github.com/kilnfi/staking-contracts/commit/60387680768fd0c9da24ab097dd7953a2b8df19d)
- [feat: slashing logic removed](https://github.com/kilnfi/staking-contracts/commit/196a1bbb1b720b1134253890e3f7010c3f3143ee)
- [feat: immutable commission limits](https://github.com/kilnfi/staking-contracts/commit/ea9f10d58b131ee40560364137a046272fe6a62a)
- [fix: split initialization](https://github.com/kilnfi/staking-contracts/commit/3aa65764f2d868d41b52aceac092cdb43a59d7a9)
- [feat: stop deposits flag](https://github.com/kilnfi/staking-contracts/commit/aad23d5b1bec1ff6c8229f0b197a4575a800614c)
- [feat: restrict withdrawal function](https://github.com/kilnfi/staking-contracts/commit/ed1b36be629b13ac4b1f417eb0da084067ef803a)
- [feat: optional AuthorizedFeeRecipient](https://github.com/kilnfi/staking-contracts/commit/35acce30b033314906ec98395c53f4fb2844b61e)

### Audit fixes
- [remove multi operator logic](https://github.com/kilnfi/staking-contracts/commit/e5c91d8a08a5fd64bddb6b5a9e09f467e0b3bbc0)
- [remove Treasury contract](https://github.com/kilnfi/staking-contracts/commit/8306951add826c11f5decc427cb0ea6d6cd889ba)
- [reset operator index when removing validators](https://github.com/kilnfi/staking-contracts/commit/8def7d680a95f66137f16ddb53ca669bf099ab04)
- [implement snapshot mechanism for stored keys](https://github.com/kilnfi/staking-contracts/commit/dc6f050b3bf1f234e89d321037a9e353127dae8a)

### Deployments

- [Ledger Komainu mainnet deployment (now Kiln dApp)](https://github.com/kilnfi/staking-contracts/commit/a74d0810a2c97b2eaaa7763bd347ed30eed2b7e2)

- [Goerli deployment](https://github.com/kilnfi/staking-contracts/commit/fb1be197899b28b3ba72a2f3af752666b5125e81)

- [Updated implementations](https://github.com/kilnfi/staking-contracts/commit/f33eb8dc37fab40217dbe1e69853ca3fcd884a2d)

- [Holesky devenet & testnet](https://github.com/kilnfi/staking-contracts/commit/6df02b9c7d003504f1b57b7ef6d639ce963943dc)

- [Consensys immutable deployment](https://github.com/kilnfi/staking-contracts/commit/53f2d9b0d0662d1f5d44fab7f04684cca56df2fb)

- [Safe promotional deployment + testnet](https://github.com/kilnfi/staking-contracts/commit/af56cf295664d61ab0e23e45d5eabf780e4e59ab)

- [Safe second deployment](https://github.com/kilnfi/staking-contracts/commit/bb8e64d583ce31b03d7f5ff613931c7819621ddb)

## v0.2.2 (September 13th 2022)

### :dizzy: Features

- [feat: add missing events](https://github.com/kilnfi/staking-contracts/pull/61)

### Deployments

- [Enzyme mainnet deployment](https://github.com/kilnfi/staking-contracts/commit/42761e7837498c27798bd15e7d0886f3dea7180b)

- [Ledger Live mainnet deployment](https://github.com/kilnfi/staking-contracts/commit/cd680d350bfe4edacadccf01b6dd1484cd8a49b0)

- [Ledger Vault mainnet deployment](https://github.com/kilnfi/staking-contracts/commit/dd41162155a5e944731d544229f2763d1a99eb9e)

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