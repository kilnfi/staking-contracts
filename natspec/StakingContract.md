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

### acceptOwnership

```solidity
function acceptOwnership() external nonpayable
```

New admin must accept its role by calling this method

*Only callable by new admin*


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
| _feeRecipientAddress | address | Privileged operator address used to manage rewards and operator addresses |

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

### batchWithdraw

```solidity
function batchWithdraw(bytes _publicKeys) external nonpayable
```

Withdraw both Consensus and Execution Layer Fees for given validators public keys

*Funds are sent to the withdrawer account*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _publicKeys | bytes | Validators to withdraw fees from |

### batchWithdrawCLFee

```solidity
function batchWithdrawCLFee(bytes _publicKeys) external nonpayable
```

Withdraw the Consensus Layer Fee for given validators public keys

*Funds are sent to the withdrawer accountThis method is public on purpose*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _publicKeys | bytes | Validators to withdraw Consensus Layer Fees from |

### batchWithdrawELFee

```solidity
function batchWithdrawELFee(bytes _publicKeys) external nonpayable
```

Withdraw the Execution Layer Fee for given validators public keys

*Funds are sent to the withdrawer accountThis method is public on purpose*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _publicKeys | bytes | Validators to withdraw Execution Layer Fees from |

### blockAccount

```solidity
function blockAccount(address _account, bytes _publicKeys) external nonpayable
```

Utility to ban a user, exits the validators provided if account is not OFAC sanctionedBlocks the account from depositing, the account is still alowed to exit &amp; withdraw if not sanctioned



#### Parameters

| Name | Type | Description |
|---|---|---|
| _account | address | Account to ban |
| _publicKeys | bytes | Public keys to exit |

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
function deposit() external payable
```

Explicit deposit method using msg.sender

*A multiple of 32 ETH should be sent*


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

### getDepositsStopped

```solidity
function getDepositsStopped() external view returns (bool)
```

Returns false if the users can deposit, true if deposits are stopped




#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | bool | undefined |

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

### getEnabledFromPublicKeyRoot

```solidity
function getEnabledFromPublicKeyRoot(bytes32 _publicKeyRoot) external view returns (bool)
```

Retrieve the enabled status of public key root, true if the key is in the contract



#### Parameters

| Name | Type | Description |
|---|---|---|
| _publicKeyRoot | bytes32 | Hash of the public key |

#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | bool | undefined |

### getExitRequestedFromRoot

```solidity
function getExitRequestedFromRoot(bytes32 _publicKeyRoot) external view returns (bool)
```

Retrieve whether the validator exit has been requestedIn case the validator is not enabled, it will return false



#### Parameters

| Name | Type | Description |
|---|---|---|
| _publicKeyRoot | bytes32 | Public Key Root to check |

#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | bool | undefined |

### getGlobalFee

```solidity
function getGlobalFee() external view returns (uint256)
```

Retrieve the global fee




#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | uint256 | undefined |

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

### getOperatorFee

```solidity
function getOperatorFee() external view returns (uint256)
```

Retrieve the operator fee




#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | uint256 | undefined |

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

### getPendingAdmin

```solidity
function getPendingAdmin() external view returns (address)
```

Get the new admin&#39;s address previously set for an ownership transfer




#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | address | undefined |

### getSanctionsOracle

```solidity
function getSanctionsOracle() external view returns (address)
```

Get the sanctions oracle addressIf the address is address(0), the sanctions oracle checks are skipped




#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | address | sanctionsOracle The sanctions oracle address |

### getTreasury

```solidity
function getTreasury() external view returns (address)
```

Retrieve system treasury




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

Retrieve withdrawer of public keyIn case the validator is not enabled, it will return address(0)



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

Retrieve withdrawer of public key rootIn case the validator is not enabled, it will return address(0)In case the owner of the validator is sanctioned, it will revert



#### Parameters

| Name | Type | Description |
|---|---|---|
| _publicKeyRoot | bytes32 | Hash of the public key |

#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | address | undefined |

### getWithdrawnFromPublicKeyRoot

```solidity
function getWithdrawnFromPublicKeyRoot(bytes32 _publicKeyRoot) external view returns (bool)
```

Return true if the validator already went through the exit logicIn case the validator is not enabled, it will return false



#### Parameters

| Name | Type | Description |
|---|---|---|
| _publicKeyRoot | bytes32 | Public Key Root of the validator |

#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | bool | undefined |

### initialize_1

```solidity
function initialize_1(address _admin, address _treasury, address _depositContract, address _elDispatcher, address _clDispatcher, address _feeRecipientImplementation, uint256 _globalFee, uint256 _operatorFee, uint256 globalCommissionLimitBPS, uint256 operatorCommissionLimitBPS) external nonpayable
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| _admin | address | undefined |
| _treasury | address | undefined |
| _depositContract | address | undefined |
| _elDispatcher | address | undefined |
| _clDispatcher | address | undefined |
| _feeRecipientImplementation | address | undefined |
| _globalFee | uint256 | undefined |
| _operatorFee | uint256 | undefined |
| globalCommissionLimitBPS | uint256 | undefined |
| operatorCommissionLimitBPS | uint256 | undefined |

### initialize_2

```solidity
function initialize_2(uint256 globalCommissionLimitBPS, uint256 operatorCommissionLimitBPS) external nonpayable
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| globalCommissionLimitBPS | uint256 | undefined |
| operatorCommissionLimitBPS | uint256 | undefined |

### isBlockedOrSanctioned

```solidity
function isBlockedOrSanctioned(address _account) external view returns (bool isBlocked, bool isSanctioned)
```

Utility to check if an account is blocked or sanctioned



#### Parameters

| Name | Type | Description |
|---|---|---|
| _account | address | Account to check |

#### Returns

| Name | Type | Description |
|---|---|---|
| isBlocked | bool | True if the account is blocked |
| isSanctioned | bool | True if the account is sanctioned, always false if not sanctions oracle is set |

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

### requestValidatorsExit

```solidity
function requestValidatorsExit(bytes _publicKeys) external nonpayable
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| _publicKeys | bytes | undefined |

### setDepositsStopped

```solidity
function setDepositsStopped(bool val) external nonpayable
```

Utility to stop or allow deposits



#### Parameters

| Name | Type | Description |
|---|---|---|
| val | bool | undefined |

### setGlobalFee

```solidity
function setGlobalFee(uint256 _globalFee) external nonpayable
```

Change the Global fee



#### Parameters

| Name | Type | Description |
|---|---|---|
| _globalFee | uint256 | Fee in Basis Point |

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

### setOperatorFee

```solidity
function setOperatorFee(uint256 _operatorFee) external nonpayable
```

Change the Operator fee



#### Parameters

| Name | Type | Description |
|---|---|---|
| _operatorFee | uint256 | Fee in Basis Point |

### setOperatorLimit

```solidity
function setOperatorLimit(uint256 _operatorIndex, uint256 _limit, uint256 _snapshot) external nonpayable
```

Set operator staking limits

*Only callable by adminLimit should not exceed the validator key count of the operatorKeys should be registered before limit is increasedAllows all keys to be verified by the system admin before limit is increased*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _operatorIndex | uint256 | Operator Index |
| _limit | uint256 | New staking limit |
| _snapshot | uint256 | Block number at which verification was done |

### setSanctionsOracle

```solidity
function setSanctionsOracle(address _sanctionsOracle) external nonpayable
```

Changes the sanctions oracle address

*If the address is address(0), the sanctions oracle checks are skipped*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _sanctionsOracle | address | New sanctions oracle address |

### setTreasury

```solidity
function setTreasury(address _newTreasury) external nonpayable
```

Set new treasury

*Only callable by admin*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _newTreasury | address | New Treasury address |

### toggleWithdrawnFromPublicKeyRoot

```solidity
function toggleWithdrawnFromPublicKeyRoot(bytes32 _publicKeyRoot) external nonpayable
```

Allows the CLDispatcher to signal a validator went through the exit logic



#### Parameters

| Name | Type | Description |
|---|---|---|
| _publicKeyRoot | bytes32 | Public Key Root of the validator |

### transferOwnership

```solidity
function transferOwnership(address _newAdmin) external nonpayable
```

Set new admin

*Only callable by admin*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _newAdmin | address | New Administrator address |

### unblock

```solidity
function unblock(address _account) external nonpayable
```

Utility to unban a user



#### Parameters

| Name | Type | Description |
|---|---|---|
| _account | address | Account to unban |

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

*Funds are sent to the withdrawer account*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _publicKey | bytes | Validator to withdraw Consensus Layer Fees from |

### withdrawELFee

```solidity
function withdrawELFee(bytes _publicKey) external nonpayable
```

Withdraw the Execution Layer Fee for a given validator public key

*Funds are sent to the withdrawer account*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _publicKey | bytes | Validator to withdraw Execution Layer Fees from |



## Events

### ActivatedOperator

```solidity
event ActivatedOperator(uint256 _operatorIndex)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| _operatorIndex  | uint256 | undefined |

### BeginOwnershipTransfer

```solidity
event BeginOwnershipTransfer(address indexed previousAdmin, address indexed newAdmin)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| previousAdmin `indexed` | address | undefined |
| newAdmin `indexed` | address | undefined |

### ChangedAdmin

```solidity
event ChangedAdmin(address newAdmin)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| newAdmin  | address | undefined |

### ChangedDepositsStopped

```solidity
event ChangedDepositsStopped(bool isStopped)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| isStopped  | bool | undefined |

### ChangedGlobalFee

```solidity
event ChangedGlobalFee(uint256 newGlobalFee)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| newGlobalFee  | uint256 | undefined |

### ChangedOperatorAddresses

```solidity
event ChangedOperatorAddresses(uint256 operatorIndex, address operatorAddress, address feeRecipientAddress)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| operatorIndex  | uint256 | undefined |
| operatorAddress  | address | undefined |
| feeRecipientAddress  | address | undefined |

### ChangedOperatorFee

```solidity
event ChangedOperatorFee(uint256 newOperatorFee)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| newOperatorFee  | uint256 | undefined |

### ChangedOperatorLimit

```solidity
event ChangedOperatorLimit(uint256 operatorIndex, uint256 limit)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| operatorIndex  | uint256 | undefined |
| limit  | uint256 | undefined |

### ChangedTreasury

```solidity
event ChangedTreasury(address newTreasury)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| newTreasury  | address | undefined |

### ChangedWithdrawer

```solidity
event ChangedWithdrawer(bytes publicKey, address newWithdrawer)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| publicKey  | bytes | undefined |
| newWithdrawer  | address | undefined |

### DeactivatedOperator

```solidity
event DeactivatedOperator(uint256 _operatorIndex)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| _operatorIndex  | uint256 | undefined |

### Deposit

```solidity
event Deposit(address indexed caller, address indexed withdrawer, bytes publicKey, bytes signature)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| caller `indexed` | address | undefined |
| withdrawer `indexed` | address | undefined |
| publicKey  | bytes | undefined |
| signature  | bytes | undefined |

### ExitRequest

```solidity
event ExitRequest(address caller, bytes pubkey)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| caller  | address | undefined |
| pubkey  | bytes | undefined |

### NewOperator

```solidity
event NewOperator(address operatorAddress, address feeRecipientAddress, uint256 index)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| operatorAddress  | address | undefined |
| feeRecipientAddress  | address | undefined |
| index  | uint256 | undefined |

### NewSanctionsOracle

```solidity
event NewSanctionsOracle(address sanctionsOracle)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| sanctionsOracle  | address | undefined |

### ValidatorKeyRemoved

```solidity
event ValidatorKeyRemoved(uint256 indexed operatorIndex, bytes publicKey)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| operatorIndex `indexed` | uint256 | undefined |
| publicKey  | bytes | undefined |

### ValidatorKeysAdded

```solidity
event ValidatorKeysAdded(uint256 indexed operatorIndex, bytes publicKeys, bytes signatures)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| operatorIndex `indexed` | uint256 | undefined |
| publicKeys  | bytes | undefined |
| signatures  | bytes | undefined |

### ValidatorsEdited

```solidity
event ValidatorsEdited(uint256 blockNumber)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| blockNumber  | uint256 | undefined |



## Errors

### AddressBlocked

```solidity
error AddressBlocked(address blockedAccount)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| blockedAccount | address | undefined |

### AddressSanctioned

```solidity
error AddressSanctioned(address sanctionedAccount)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| sanctionedAccount | address | undefined |

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






### DepositsStopped

```solidity
error DepositsStopped()
```






### DuplicateValidatorKey

```solidity
error DuplicateValidatorKey(bytes)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| _0 | bytes | undefined |

### Forbidden

```solidity
error Forbidden()
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






### InvalidWithdrawer

```solidity
error InvalidWithdrawer()
```






### InvalidZeroAddress

```solidity
error InvalidZeroAddress()
```






### LastEditAfterSnapshot

```solidity
error LastEditAfterSnapshot()
```






### MaximumOperatorCountAlreadyReached

```solidity
error MaximumOperatorCountAlreadyReached()
```






### NoOperators

```solidity
error NoOperators()
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

### PublicKeyNotInContract

```solidity
error PublicKeyNotInContract()
```






### Unauthorized

```solidity
error Unauthorized()
```






### UnsortedIndexes

```solidity
error UnsortedIndexes()
```







