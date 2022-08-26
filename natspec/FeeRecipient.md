# FeeRecipient









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

### getWithdrawer

```solidity
function getWithdrawer() external view returns (address)
```

retrieve the assigned withdrawer




#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | address | undefined |

### init

```solidity
function init(address _dispatcher, bytes32 _publicKeyRoot) external nonpayable
```

Initializes the receiver



#### Parameters

| Name | Type | Description |
|---|---|---|
| _dispatcher | address | Address that will handle the fee dispatching |
| _publicKeyRoot | bytes32 | Public Key root assigned to this receiver |

### withdraw

```solidity
function withdraw() external nonpayable
```

Triggers a withdrawal by sending its funds + its public key root to the dispatcher

*Can be called by any wallet as recipients are not parameters*





## Errors

### AlreadyInitialized

```solidity
error AlreadyInitialized()
```







