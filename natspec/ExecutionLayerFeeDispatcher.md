# ExecutionLayerFeeDispatcher

*Kiln*

> Execution Layer Fee Recipient

This contract can be used to receive fees from a validator and split them with a node operator



## Methods

### dispatch

```solidity
function dispatch(bytes32 _publicKeyRoot) external payable
```

Performs a withdrawal on this contract&#39;s balance



#### Parameters

| Name | Type | Description |
|---|---|---|
| _publicKeyRoot | bytes32 | undefined |

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
function getWithdrawer(bytes32 _publicKeyRoot) external view returns (address)
```

Retrieve the assigned withdrawer for the given public key root



#### Parameters

| Name | Type | Description |
|---|---|---|
| _publicKeyRoot | bytes32 | Public key root to get the owner |

#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | address | undefined |

### initELD

```solidity
function initELD(address _stakingContract) external nonpayable
```

Initialize the contract by storing the staking contract and the public key in storage



#### Parameters

| Name | Type | Description |
|---|---|---|
| _stakingContract | address | Address of the Staking Contract |



## Events

### Withdrawal

```solidity
event Withdrawal(address indexed withdrawer, address indexed feeRecipient, bytes32 pubKeyRoot, uint256 rewards, uint256 nodeOperatorFee, uint256 treasuryFee)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| withdrawer `indexed` | address | undefined |
| feeRecipient `indexed` | address | undefined |
| pubKeyRoot  | bytes32 | undefined |
| rewards  | uint256 | undefined |
| nodeOperatorFee  | uint256 | undefined |
| treasuryFee  | uint256 | undefined |



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






### TreasuryReceiveError

```solidity
error TreasuryReceiveError(bytes errorData)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| errorData | bytes | undefined |

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







