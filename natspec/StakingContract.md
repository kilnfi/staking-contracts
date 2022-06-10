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

### addOperator

```solidity
function addOperator(address _operatorAddress) external nonpayable returns (uint256)
```

Add new operator

*Only callable by admin*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _operatorAddress | address | Operator address allowed to add / remove validators |

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

Get the total available keys that are redy to be used for deposits




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

### getFeeTreasury

```solidity
function getFeeTreasury(bytes32 pubKeyRoot) external view returns (address)
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

### getOperator

```solidity
function getOperator(uint256 _operatorIndex) external view returns (address operatorAddress, uint256 limit, uint256 keys, uint256 funded, uint256 available)
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
| limit | uint256 | undefined |
| keys | uint256 | undefined |
| funded | uint256 | undefined |
| available | uint256 | undefined |

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
function initialize_1(address _admin, address _depositContract, address _elFeeRecipientImplementation, address _clFeeRecipientImplementation, bytes32 _withdrawalCredentials, uint256 _elFee, uint256 _clFee) external nonpayable
```

Initializes version 1 of Staking Contract



#### Parameters

| Name | Type | Description |
|---|---|---|
| _admin | address | Address of the admin allowed to change the operator and admin |
| _depositContract | address | Address of the Deposit Contract |
| _elFeeRecipientImplementation | address | undefined |
| _clFeeRecipientImplementation | address | undefined |
| _withdrawalCredentials | bytes32 | Withdrawal Credentials to apply to all provided keys upon deposit |
| _elFee | uint256 | undefined |
| _clFee | uint256 | undefined |

### removeValidators

```solidity
function removeValidators(uint256 _operatorIndex, uint256[] _indexes) external nonpayable
```

Remove unfunded validators

*Only callable by operatorIndexes should be provided in decreasing order*

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

### setOperatorLimit

```solidity
function setOperatorLimit(uint256 _operatorIndex, uint256 _limit) external nonpayable
```

Set operator staking limits

*Only callable by admin*

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






### InvalidFee

```solidity
error InvalidFee()
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






### Unauthorized

```solidity
error Unauthorized()
```






### UnsortedIndexes

```solidity
error UnsortedIndexes()
```







