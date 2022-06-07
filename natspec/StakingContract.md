# StakingContract

*SkillZ*

> Ethereum Staking Contract

You can use this contract to store validator keys and have users fund them and trigger deposits.



## Methods

### DEPOSIT_SIZE

```solidity
function DEPOSIT_SIZE() external view returns (uint256)
```






#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | uint256 | undefined |

### PUBLIC_KEY_LENGTH

```solidity
function PUBLIC_KEY_LENGTH() external view returns (uint256)
```






#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | uint256 | undefined |

### SIGNATURE_LENGTH

```solidity
function SIGNATURE_LENGTH() external view returns (uint256)
```






#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | uint256 | undefined |

### deposit

```solidity
function deposit(address _withdrawer) external payable
```

Explicit deposit method

*A multiple of 32 ETH should be sent*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _withdrawer | address | The withdrawer address |

### fundedValidatorsCount

```solidity
function fundedValidatorsCount() external view returns (uint256)
```

Retrieve the amount of funded validators




#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | uint256 | undefined |

### getAdmin

```solidity
function getAdmin() external view returns (address)
```

Retrieve the admin address




#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | address | undefined |

### getOperator

```solidity
function getOperator() external view returns (address)
```

Retrieve the operator address




#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | address | undefined |

### getValidator

```solidity
function getValidator(uint256 _idx) external view returns (bytes publicKey, bytes signature, address withdrawer, bool funded)
```

Retrieve the details of a validator



#### Parameters

| Name | Type | Description |
|---|---|---|
| _idx | uint256 | Index of the validator |

#### Returns

| Name | Type | Description |
|---|---|---|
| publicKey | bytes | undefined |
| signature | bytes | undefined |
| withdrawer | address | undefined |
| funded | bool | undefined |

### getWithdrawer

```solidity
function getWithdrawer(bytes _publicKey) external view returns (address)
```

Retrieve the withdrawer for a specific public key



#### Parameters

| Name | Type | Description |
|---|---|---|
| _publicKey | bytes | Public Key to retrieve the withdrawer |

#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | address | undefined |

### initialize_1

```solidity
function initialize_1(address _operator, address _admin, address _depositContract, bytes32 _withdrawalCredentials) external nonpayable
```

Initializes version 1 of Staking Contract



#### Parameters

| Name | Type | Description |
|---|---|---|
| _operator | address | Address of the operator allowed to add/remove keys |
| _admin | address | Address of the admin allowed to change the operator and admin |
| _depositContract | address | Address of the Deposit Contract |
| _withdrawalCredentials | bytes32 | Withdrawal Credentials to apply to all provided keys upon deposit |

### registerValidators

```solidity
function registerValidators(uint256 keyCount, bytes publicKeys, bytes signatures) external nonpayable
```

Register new validators

*Only the operator or the admin are allowed to call this methodpublickKeys is the concatenation of keyCount public keyssignatures is the concatenation of keyCount signatures*

#### Parameters

| Name | Type | Description |
|---|---|---|
| keyCount | uint256 | The expected number of keys from publicKeys and signatures |
| publicKeys | bytes | Concatenated public keys |
| signatures | bytes | Concatenated signatures |

### removeValidators

```solidity
function removeValidators(uint256[] _indexes) external nonpayable
```

Remove validators

*Only the operator or the admin are allowed to call this methodThe indexes to delete should all be greater than the amount of funded validatorsThe indexes to delete should be sorted in descending order or the method will fail*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _indexes | uint256[] | The indexes to delete |

### setAdmin

```solidity
function setAdmin(address _newAdmin) external nonpayable
```

Change the admin address

*Only the admin is allowed to call this method*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _newAdmin | address | New Admin address |

### setOperator

```solidity
function setOperator(address _newOperator) external nonpayable
```

Change the operator address

*Only the admin or the operator are allowed to call this method*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _newOperator | address | New Operator address |

### setWithdrawer

```solidity
function setWithdrawer(bytes _publicKey, address _newWithdrawer) external nonpayable
```

Change the withdrawer for a specific public key

*Only the previous withdrawer of the public key can change the withdrawer*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _publicKey | bytes | The public key to change |
| _newWithdrawer | address | The new withdrawer address |

### totalValidatorCount

```solidity
function totalValidatorCount() external view returns (uint256)
```

Retrieve the amount of registered validators (funded + not yet funded)




#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | uint256 | undefined |



## Events

### Deposit

```solidity
event Deposit(address indexed caller, address indexed withdrawer, bytes publicKey, bytes32 publicKeyRoot)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| caller `indexed` | address | undefined |
| withdrawer `indexed` | address | undefined |
| publicKey  | bytes | undefined |
| publicKeyRoot  | bytes32 | undefined |



## Errors

### AlreadyInitialized

```solidity
error AlreadyInitialized()
```






### DepositFailure

```solidity
error DepositFailure()
```






### FundedValidatorDeletionAttempt

```solidity
error FundedValidatorDeletionAttempt()
```






### InvalidArgument

```solidity
error InvalidArgument()
```






### InvalidCall

```solidity
error InvalidCall()
```






### InvalidMessageValue

```solidity
error InvalidMessageValue()
```






### InvalidPublicKeys

```solidity
error InvalidPublicKeys()
```






### InvalidSignatures

```solidity
error InvalidSignatures()
```






### NotEnoughKeys

```solidity
error NotEnoughKeys()
```






### Unauthorized

```solidity
error Unauthorized()
```






### UnsortedIndexes

```solidity
error UnsortedIndexes()
```







