# StakingContract

*Kiln*

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

### activateOperator

```solidity
function activateOperator(uint256 _operatorIndex, address _newFeeRecipient) external nonpayable
```

Activates an operator, without changing its 0 staking limit



#### Parameters

| Name | Type | Description |
|---|---|---|
| _operatorIndex | uint256 | Operator Index |
| _newFeeRecipient | address | Sets the fee recipient address |

### addOperator

```solidity
function addOperator(address _operatorAddress, address _feeRecipientAddress) external nonpayable returns (uint256)
```

Add new operator

*Only callable by admin*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _operatorAddress | address | Operator address allowed to add / remove validators |
| _feeRecipientAddress | address | Operator address used to manage rewards |

#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | uint256 | undefined |

### addValidators

```solidity
function addValidators(uint256 _operatorIndex, uint256 _keyCount, bytes _publicKeys, bytes _signatures) external nonpayable
```

Add new validator public keys and signatures

*Only callable by operator*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _operatorIndex | uint256 | Operator Index |
| _keyCount | uint256 | Number of keys added |
| _publicKeys | bytes | Concatenated _keyCount public keys |
| _signatures | bytes | Concatenated _keyCount signatures |

### deactivateOperator

```solidity
function deactivateOperator(uint256 _operatorIndex, address _temporaryFeeRecipient) external nonpayable
```

Deactivates an operator and changes the fee recipient address and the staking limit



#### Parameters

| Name | Type | Description |
|---|---|---|
| _operatorIndex | uint256 | Operator Index |
| _temporaryFeeRecipient | address | Temporary address to receive funds decided by the system admin |

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

### getAdmin

```solidity
function getAdmin() external view returns (address)
```

Retrieve system admin




#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | address | undefined |

### getAvailableValidatorCount

```solidity
function getAvailableValidatorCount() external view returns (uint256)
```

Get the total available keys that are ready to be used for deposits




#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | uint256 | undefined |

### getCLFee

```solidity
function getCLFee() external view returns (uint256)
```

Retrieve the Consensus Layer Fee taken by the node operator




#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | uint256 | undefined |

### getCLFeeRecipient

```solidity
function getCLFeeRecipient(bytes _publicKey) external view returns (address)
```

Compute the Consensus Layer Fee recipient address for a given validator public key



#### Parameters

| Name | Type | Description |
|---|---|---|
| _publicKey | bytes | Validator to get the recipient |

#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | address | undefined |

### getELFee

```solidity
function getELFee() external view returns (uint256)
```

Retrieve the Execution Layer Fee taken by the node operator




#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | uint256 | undefined |

### getELFeeRecipient

```solidity
function getELFeeRecipient(bytes _publicKey) external view returns (address)
```

Compute the Execution Layer Fee recipient address for a given validator public key



#### Parameters

| Name | Type | Description |
|---|---|---|
| _publicKey | bytes | Validator to get the recipient |

#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | address | undefined |

### getOperator

```solidity
function getOperator(uint256 _operatorIndex) external view returns (address operatorAddress, address feeRecipientAddress, uint256 limit, uint256 keys, uint256 funded, uint256 available, bool deactivated)
```

Retrieve operator details



#### Parameters

| Name | Type | Description |
|---|---|---|
| _operatorIndex | uint256 | Operator index |

#### Returns

| Name | Type | Description |
|---|---|---|
| operatorAddress | address | undefined |
| feeRecipientAddress | address | undefined |
| limit | uint256 | undefined |
| keys | uint256 | undefined |
| funded | uint256 | undefined |
| available | uint256 | undefined |
| deactivated | bool | undefined |

### getOperatorFeeRecipient

```solidity
function getOperatorFeeRecipient(bytes32 pubKeyRoot) external view returns (address)
```

Retrieve the Execution &amp; Consensus Layer Fee operator recipient for a given public key



#### Parameters

| Name | Type | Description |
|---|---|---|
| pubKeyRoot | bytes32 | undefined |

#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | address | undefined |

### getValidator

```solidity
function getValidator(uint256 _operatorIndex, uint256 _validatorIndex) external view returns (bytes publicKey, bytes signature, address withdrawer, bool funded)
```

Get details about a validator



#### Parameters

| Name | Type | Description |
|---|---|---|
| _operatorIndex | uint256 | Index of the operator running the validator |
| _validatorIndex | uint256 | Index of the validator |

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

Retrieve withdrawer of public key



#### Parameters

| Name | Type | Description |
|---|---|---|
| _publicKey | bytes | Public Key to check |

#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | address | undefined |

### getWithdrawerFromPublicKeyRoot

```solidity
function getWithdrawerFromPublicKeyRoot(bytes32 _publicKeyRoot) external view returns (address)
```

Retrieve withdrawer of public key root



#### Parameters

| Name | Type | Description |
|---|---|---|
| _publicKeyRoot | bytes32 | Hash of the public key |

#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | address | undefined |

### initialize_1

```solidity
function initialize_1(address _admin, address _depositContract, address _elDispatcher, address _clDispatcher, address _minimalReceiverImplementation, uint256 _elFee, uint256 _clFee) external nonpayable
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| _admin | address | undefined |
| _depositContract | address | undefined |
| _elDispatcher | address | undefined |
| _clDispatcher | address | undefined |
| _minimalReceiverImplementation | address | undefined |
| _elFee | uint256 | undefined |
| _clFee | uint256 | undefined |

### removeValidators

```solidity
function removeValidators(uint256 _operatorIndex, uint256[] _indexes) external nonpayable
```

Remove unfunded validators

*Only callable by operatorIndexes should be provided in decreasing orderThe limit will be set to the lowest removed operator index to ensure all changes above the      lowest removed validator key are verified by the system administrator*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _operatorIndex | uint256 | Operator Index |
| _indexes | uint256[] | List of indexes to delete, in decreasing order |

### setAdmin

```solidity
function setAdmin(address _newAdmin) external nonpayable
```

Set new admin

*Only callable by admin*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _newAdmin | address | New Administrator address |

### setCLFee

```solidity
function setCLFee(uint256 _fee) external nonpayable
```

Change the Consensus Layer Fee taken by the node operator



#### Parameters

| Name | Type | Description |
|---|---|---|
| _fee | uint256 | Fee in Basis Point |

### setELFee

```solidity
function setELFee(uint256 _fee) external nonpayable
```

Change the Execution Layer Fee taken by the node operator



#### Parameters

| Name | Type | Description |
|---|---|---|
| _fee | uint256 | Fee in Basis Point |

### setOperatorAddresses

```solidity
function setOperatorAddresses(uint256 _operatorIndex, address _operatorAddress, address _feeRecipientAddress) external nonpayable
```

Set new operator addresses (operations and reward management)

*Only callable by fee recipient address manager*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _operatorIndex | uint256 | Index of the operator to update |
| _operatorAddress | address | New operator address for operations management |
| _feeRecipientAddress | address | New operator address for reward management |

### setOperatorLimit

```solidity
function setOperatorLimit(uint256 _operatorIndex, uint256 _limit) external nonpayable
```

Set operator staking limits

*Only callable by adminLimit should not exceed the validator key count of the operatorKeys should be registered before limit is increasedAllows all keys to be verified by the system admin before limit is increased*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _operatorIndex | uint256 | Operator Index |
| _limit | uint256 | New staking limit |

### setWithdrawer

```solidity
function setWithdrawer(bytes _publicKey, address _newWithdrawer) external nonpayable
```

Set withdrawer for public key

*Only callable by current public key withdrawer*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _publicKey | bytes | Public key to change withdrawer |
| _newWithdrawer | address | New withdrawer address |

### withdraw

```solidity
function withdraw(bytes _publicKey) external nonpayable
```

Withdraw both Consensus and Execution Layer Fee for a given validator public key

*Reverts if any is null*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _publicKey | bytes | Validator to withdraw Execution and Consensus Layer Fees from |

### withdrawCLFee

```solidity
function withdrawCLFee(bytes _publicKey) external nonpayable
```

Withdraw the Consensus Layer Fee for a given validator public key

*Funds are sent to the withdrawer accountThis method is public on purpose*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _publicKey | bytes | Validator to withdraw Consensus Layer Fees from |

### withdrawELFee

```solidity
function withdrawELFee(bytes _publicKey) external nonpayable
```

Withdraw the Execution Layer Fee for a given validator public key

*Funds are sent to the withdrawer accountThis method is public on purpose*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _publicKey | bytes | Validator to withdraw Execution Layer Fees from |



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






### Deactivated

```solidity
error Deactivated()
```






### DepositFailure

```solidity
error DepositFailure()
```






### DuplicateValidatorKey

```solidity
error DuplicateValidatorKey(bytes)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| _0 | bytes | undefined |

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






### InvalidDepositValue

```solidity
error InvalidDepositValue()
```






### InvalidFee

```solidity
error InvalidFee()
```






### InvalidPublicKeys

```solidity
error InvalidPublicKeys()
```






### InvalidSignatures

```solidity
error InvalidSignatures()
```






### InvalidValidatorCount

```solidity
error InvalidValidatorCount()
```






### NoOperators

```solidity
error NoOperators()
```






### NotEnoughKeys

```solidity
error NotEnoughKeys()
```






### NotEnoughValidators

```solidity
error NotEnoughValidators()
```






### OperatorLimitTooHigh

```solidity
error OperatorLimitTooHigh(uint256 limit, uint256 keyCount)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| limit | uint256 | undefined |
| keyCount | uint256 | undefined |

### Unauthorized

```solidity
error Unauthorized()
```






### UnsortedIndexes

```solidity
error UnsortedIndexes()
```







