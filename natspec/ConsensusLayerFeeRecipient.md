# ConsensusLayerFeeRecipient

*Kiln*

> Consensus Layer Fee Recipient

This contract can be used to receive fees from a validator and split them with a node operator



## Methods

### getPublicKeyRoot

```solidity
function getPublicKeyRoot() external view returns (bytes32)
```

Retrieve the assigned public key root




#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | bytes32 | undefined |

### getStakingContract

```solidity
function getStakingContract() external view returns (address)
```

Retrieve the staking contract address




#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | address | undefined |

### getWithdrawer

```solidity
function getWithdrawer() external view returns (address)
```

Retrieve the assigned withdrawer




#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | address | undefined |

### initCLFR

```solidity
function initCLFR(address _stakingContract, bytes32 _publicKeyRoot) external nonpayable
```

Initialize the contract by storing the staking contract and the public key in storage



#### Parameters

| Name | Type | Description |
|---|---|---|
| _stakingContract | address | Address of the Staking Contract |
| _publicKeyRoot | bytes32 | Hash of the public key linked to this fee recipient |

### withdraw

```solidity
function withdraw() external nonpayable
```

Performs a withdrawal on this contract&#39;s balance






## Events

### Withdrawal

```solidity
event Withdrawal(address indexed withdrawer, address indexed feeRecipient, uint256 rewards, uint256 fee)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| withdrawer `indexed` | address | undefined |
| feeRecipient `indexed` | address | undefined |
| rewards  | uint256 | undefined |
| fee  | uint256 | undefined |



## Errors

### AlreadyInitialized

```solidity
error AlreadyInitialized()
```






### FeeRecipientReceiveError

```solidity
error FeeRecipientReceiveError(bytes errorData)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| errorData | bytes | undefined |

### InvalidCall

```solidity
error InvalidCall()
```






### WithdrawerReceiveError

```solidity
error WithdrawerReceiveError(bytes errorData)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| errorData | bytes | undefined |

### ZeroBalanceWithdrawal

```solidity
error ZeroBalanceWithdrawal()
```







