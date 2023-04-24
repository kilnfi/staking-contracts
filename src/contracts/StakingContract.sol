//SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.10;

import "./libs/UintLib.sol";
import "./libs/BytesLib.sol";
import "./interfaces/IFeeRecipient.sol";
import "./interfaces/IDepositContract.sol";
import "./libs/StakingContractStorageLib.sol";
import "@openzeppelin/contracts/proxy/Clones.sol";

/// @title Ethereum Staking Contract
/// @author Kiln
/// @notice You can use this contract to store validator keys and have users fund them and trigger deposits.
contract StakingContract {
    using StakingContractStorageLib for bytes32;

    uint256 internal constant EXECUTION_LAYER_SALT_PREFIX = 0;
    uint256 internal constant CONSENSUS_LAYER_SALT_PREFIX = 1;
    uint256 public constant SIGNATURE_LENGTH = 96;
    uint256 public constant PUBLIC_KEY_LENGTH = 48;
    uint256 public constant DEPOSIT_SIZE = 32 ether;
    uint256 internal constant BASIS_POINTS = 10_000;

    error Forbidden();
    error InvalidFee();
    error Deactivated();
    error NoOperators();
    error InvalidCall();
    error Unauthorized();
    error DepositFailure();
    error DepositsStopped();
    error InvalidArgument();
    error UnsortedIndexes();
    error InvalidPublicKeys();
    error InvalidSignatures();
    error InvalidWithdrawer();
    error AlreadyInitialized();
    error InvalidDepositValue();
    error NotEnoughValidators();
    error InvalidValidatorCount();
    error DuplicateValidatorKey(bytes);
    error FundedValidatorDeletionAttempt();
    error OperatorLimitTooHigh(uint256 limit, uint256 keyCount);
    error MaximumOperatorCountAlreadyReached();

    struct ValidatorAllocationCache {
        bool used;
        uint8 operatorIndex;
        uint32 funded;
        uint32 toDeposit;
        uint32 available;
    }

    event Deposit(address indexed caller, address indexed withdrawer, bytes publicKey, bytes signature);
    event ValidatorKeysAdded(uint256 indexed operatorIndex, bytes publicKeys, bytes signatures);
    event ValidatorKeyRemoved(uint256 indexed operatorIndex, bytes publicKey);
    event ChangedWithdrawer(bytes publicKey, address newWithdrawer);
    event ChangedOperatorLimit(uint256 operatorIndex, uint256 limit);
    event ChangedTreasury(address newTreasury);
    event ChangedGlobalFee(uint256 newGlobalFee);
    event ChangedOperatorFee(uint256 newOperatorFee);
    event ChangedAdmin(address newAdmin);
    event ChangedDepositsStopped(bool isStopped);
    event NewOperator(address operatorAddress, address feeRecipientAddress, uint256 index);
    event ChangedOperatorAddresses(uint256 operatorIndex, address operatorAddress, address feeRecipientAddress);
    event DeactivatedOperator(uint256 _operatorIndex);
    event ActivatedOperator(uint256 _operatorIndex);
    event SetWithdrawerCustomizationStatus(bool _status);
    event ExitRequest(address caller, bytes pubkey);

    /// @notice Ensures an initialisation call has been called only once per _version value
    /// @param _version The current initialisation value
    modifier init(uint256 _version) {
        if (_version != StakingContractStorageLib.getVersion() + 1) {
            revert AlreadyInitialized();
        }

        StakingContractStorageLib.setVersion(_version);
        _;
    }

    /// @notice Ensures that the caller is the admin
    modifier onlyAdmin() {
        if (msg.sender != StakingContractStorageLib.getAdmin()) {
            revert Unauthorized();
        }

        _;
    }

    /// @notice Ensures that the caller is the admin or the operator
    modifier onlyActiveOperatorOrAdmin(uint256 _operatorIndex) {
        if (msg.sender == StakingContractStorageLib.getAdmin()) {
            _;
        } else {
            _onlyActiveOperator(_operatorIndex);
            _;
        }
    }

    /// @notice Ensures that the caller is the admin
    modifier onlyActiveOperator(uint256 _operatorIndex) {
        _onlyActiveOperator(_operatorIndex);
        _;
    }

    /// @notice Ensures that the caller is the operator fee recipient
    modifier onlyOperatorFeeRecipient(uint256 _operatorIndex) {
        StakingContractStorageLib.OperatorInfo storage operatorInfo = StakingContractStorageLib.getOperators().value[
            _operatorIndex
        ];

        if (operatorInfo.deactivated) {
            revert Deactivated();
        }

        if (msg.sender != operatorInfo.feeRecipient) {
            revert Unauthorized();
        }

        _;
    }

    /// @notice Explicit deposit method using msg.sender
    /// @dev A multiple of 32 ETH should be sent
    function deposit() external payable {
        _deposit(msg.sender);
    }

    /// @notice Implicit deposit method
    /// @dev A multiple of 32 ETH should be sent
    /// @dev The withdrawer is set to the message sender address
    receive() external payable {
        _deposit(msg.sender);
    }

    /// @notice Fallback detection
    /// @dev Fails on any call that fallbacks
    fallback() external payable {
        revert InvalidCall();
    }

    function initialize_1(
        address _admin,
        address _treasury,
        address _depositContract,
        address _elDispatcher,
        address _clDispatcher,
        address _feeRecipientImplementation,
        uint256 _globalFee,
        uint256 _operatorFee,
        uint256 globalCommissionLimitBPS,
        uint256 operatorCommissionLimitBPS
    ) external init(1) {
        StakingContractStorageLib.setAdmin(_admin);
        StakingContractStorageLib.setTreasury(_treasury);

        if (_globalFee > BASIS_POINTS) {
            revert InvalidFee();
        }
        StakingContractStorageLib.setGlobalFee(_globalFee);
        if (_operatorFee > BASIS_POINTS) {
            revert InvalidFee();
        }
        StakingContractStorageLib.setOperatorFee(_operatorFee);

        StakingContractStorageLib.setELDispatcher(_elDispatcher);
        StakingContractStorageLib.setCLDispatcher(_clDispatcher);
        StakingContractStorageLib.setDepositContract(_depositContract);
        StakingContractStorageLib.setFeeRecipientImplementation(_feeRecipientImplementation);
        initialize_2(globalCommissionLimitBPS, operatorCommissionLimitBPS);
    }

    function initialize_2(uint256 globalCommissionLimitBPS, uint256 operatorCommissionLimitBPS) public init(2) {
        if (globalCommissionLimitBPS > BASIS_POINTS) {
            revert InvalidFee();
        }
        StakingContractStorageLib.setGlobalCommissionLimit(globalCommissionLimitBPS);
        if (operatorCommissionLimitBPS > BASIS_POINTS) {
            revert InvalidFee();
        }
        StakingContractStorageLib.setOperatorCommissionLimit(operatorCommissionLimitBPS);
    }

    /// @notice Changes the behavior of the withdrawer customization logic
    /// @param _enabled True to allow users to customize the withdrawer
    function setWithdrawerCustomizationEnabled(bool _enabled) external onlyAdmin {
        StakingContractStorageLib.setWithdrawerCustomizationEnabled(_enabled);
        emit SetWithdrawerCustomizationStatus(_enabled);
    }

    /// @notice Retrieve system admin
    function getAdmin() external view returns (address) {
        return StakingContractStorageLib.getAdmin();
    }

    /// @notice Set new treasury
    /// @dev Only callable by admin
    /// @param _newTreasury New Treasury address
    function setTreasury(address _newTreasury) external onlyAdmin {
        emit ChangedTreasury(_newTreasury);
        StakingContractStorageLib.setTreasury(_newTreasury);
    }

    /// @notice Retrieve system treasury
    function getTreasury() external view returns (address) {
        return StakingContractStorageLib.getTreasury();
    }

    /// @notice Retrieve the global fee
    function getGlobalFee() external view returns (uint256) {
        return StakingContractStorageLib.getGlobalFee();
    }

    /// @notice Retrieve the operator fee
    function getOperatorFee() external view returns (uint256) {
        return StakingContractStorageLib.getOperatorFee();
    }

    /// @notice Compute the Execution Layer Fee recipient address for a given validator public key
    /// @param _publicKey Validator to get the recipient
    function getELFeeRecipient(bytes calldata _publicKey) external view returns (address) {
        return _getDeterministicReceiver(_publicKey, EXECUTION_LAYER_SALT_PREFIX);
    }

    /// @notice Compute the Consensus Layer Fee recipient address for a given validator public key
    /// @param _publicKey Validator to get the recipient
    function getCLFeeRecipient(bytes calldata _publicKey) external view returns (address) {
        return _getDeterministicReceiver(_publicKey, CONSENSUS_LAYER_SALT_PREFIX);
    }

    /// @notice Retrieve the Execution & Consensus Layer Fee operator recipient for a given public key
    function getOperatorFeeRecipient(bytes32 pubKeyRoot) external view returns (address) {
        return
            StakingContractStorageLib
                .getOperators()
                .value[StakingContractStorageLib.getOperatorIndexPerValidator().value[pubKeyRoot].operatorIndex]
                .feeRecipient;
    }

    /// @notice Retrieve withdrawer of public key
    /// @param _publicKey Public Key to check
    function getWithdrawer(bytes calldata _publicKey) external view returns (address) {
        return _getWithdrawer(_getPubKeyRoot(_publicKey));
    }

    /// @notice Retrieve withdrawer of public key root
    /// @param _publicKeyRoot Hash of the public key
    function getWithdrawerFromPublicKeyRoot(bytes32 _publicKeyRoot) external view returns (address) {
        return _getWithdrawer(_publicKeyRoot);
    }

    /// @notice Retrieve whether the validator exit has been requested
    /// @param _publicKeyRoot Public Key Root to check
    function getExitRequestedFromRoot(bytes32 _publicKeyRoot) external view returns (bool) {
        return _getExitRequest(_publicKeyRoot);
    }

    /// @notice Return true if the validator already went through the exit logic
    /// @param _publicKeyRoot Public Key Root of the validator
    function getWithdrawnFromPublicKeyRoot(bytes32 _publicKeyRoot) external view returns (bool) {
        return StakingContractStorageLib.getWithdrawnMap().value[_publicKeyRoot];
    }

    /// @notice Allows the CLDispatcher to signal a validator went through the exit logic
    /// @param _publicKeyRoot Public Key Root of the validator
    function toggleWithdrawnFromPublicKeyRoot(bytes32 _publicKeyRoot) external {
        if (msg.sender != StakingContractStorageLib.getCLDispatcher()) {
            revert Unauthorized();
        }
        StakingContractStorageLib.getWithdrawnMap().value[_publicKeyRoot] = true;
    }

    /// @notice Returns false if the users can deposit, true if deposits are stopped
    function getDepositsStopped() external view returns (bool) {
        return StakingContractStorageLib.getDepositStopped();
    }

    /// @notice Retrieve operator details
    /// @param _operatorIndex Operator index
    function getOperator(uint256 _operatorIndex)
        external
        view
        returns (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        )
    {
        StakingContractStorageLib.OperatorsSlot storage operators = StakingContractStorageLib.getOperators();
        if (_operatorIndex < operators.value.length) {
            StakingContractStorageLib.ValidatorsFundingInfo memory _operatorInfo = StakingContractStorageLib
                .getValidatorsFundingInfo(_operatorIndex);
            StakingContractStorageLib.OperatorInfo storage _operator = operators.value[_operatorIndex];

            (operatorAddress, feeRecipientAddress, limit, keys, deactivated) = (
                _operator.operator,
                _operator.feeRecipient,
                _operator.limit,
                _operator.publicKeys.length,
                _operator.deactivated
            );
            (funded, available) = (_operatorInfo.funded, _operatorInfo.availableKeys);
        }
    }

    /// @notice Get details about a validator
    /// @param _operatorIndex Index of the operator running the validator
    /// @param _validatorIndex Index of the validator
    function getValidator(uint256 _operatorIndex, uint256 _validatorIndex)
        external
        view
        returns (
            bytes memory publicKey,
            bytes memory signature,
            address withdrawer,
            bool funded
        )
    {
        StakingContractStorageLib.OperatorsSlot storage operators = StakingContractStorageLib.getOperators();
        publicKey = operators.value[_operatorIndex].publicKeys[_validatorIndex];
        signature = operators.value[_operatorIndex].signatures[_validatorIndex];
        withdrawer = _getWithdrawer(_getPubKeyRoot(publicKey));
        funded = _validatorIndex < StakingContractStorageLib.getValidatorsFundingInfo(_operatorIndex).funded;
    }

    /// @notice Get the total available keys that are ready to be used for deposits
    function getAvailableValidatorCount() external view returns (uint256) {
        return StakingContractStorageLib.getTotalAvailableValidators();
    }

    /// @notice Set new admin
    /// @dev Only callable by admin
    /// @param _newAdmin New Administrator address
    function transferOwnership(address _newAdmin) external onlyAdmin {
        StakingContractStorageLib.setPendingAdmin(_newAdmin);
    }

    /// @notice New admin must accept its role by calling this method
    /// @dev Only callable by new admin
    function acceptOwnership() external {
        address newAdmin = StakingContractStorageLib.getPendingAdmin();

        if (msg.sender != newAdmin) {
            revert Unauthorized();
        }
        StakingContractStorageLib.setAdmin(newAdmin);
        emit ChangedAdmin(newAdmin);
    }

    /// @notice Get the new admin's address previously set for an ownership transfer
    function getPendingAdmin() external view returns (address) {
        return StakingContractStorageLib.getPendingAdmin();
    }

    /// @notice Add new operator
    /// @dev Only callable by admin
    /// @param _operatorAddress Operator address allowed to add / remove validators
    /// @param _feeRecipientAddress Operator address used to manage rewards
    function addOperator(address _operatorAddress, address _feeRecipientAddress) external onlyAdmin returns (uint256) {
        StakingContractStorageLib.OperatorsSlot storage operators = StakingContractStorageLib.getOperators();
        StakingContractStorageLib.OperatorInfo memory newOperator;

        if (operators.value.length == 1) {
            revert MaximumOperatorCountAlreadyReached();
        }
        newOperator.operator = _operatorAddress;
        newOperator.feeRecipient = _feeRecipientAddress;
        operators.value.push(newOperator);
        uint256 operatorIndex = operators.value.length - 1;
        emit NewOperator(_operatorAddress, _feeRecipientAddress, operatorIndex);
        return operatorIndex;
    }

    /// @notice Set new operator addresses (operations and reward management)
    /// @dev Only callable by fee recipient address manager
    /// @param _operatorIndex Index of the operator to update
    /// @param _operatorAddress New operator address for operations management
    /// @param _feeRecipientAddress New operator address for reward management
    function setOperatorAddresses(
        uint256 _operatorIndex,
        address _operatorAddress,
        address _feeRecipientAddress
    ) external onlyOperatorFeeRecipient(_operatorIndex) {
        StakingContractStorageLib.OperatorsSlot storage operators = StakingContractStorageLib.getOperators();

        operators.value[_operatorIndex].operator = _operatorAddress;
        operators.value[_operatorIndex].feeRecipient = _feeRecipientAddress;
        emit ChangedOperatorAddresses(_operatorIndex, _operatorAddress, _feeRecipientAddress);
    }

    /// @notice Set withdrawer for public key
    /// @dev Only callable by current public key withdrawer
    /// @param _publicKey Public key to change withdrawer
    /// @param _newWithdrawer New withdrawer address
    function setWithdrawer(bytes calldata _publicKey, address _newWithdrawer) external {
        if (!StakingContractStorageLib.getWithdrawerCustomizationEnabled()) {
            revert Forbidden();
        }
        bytes32 pubkeyRoot = sha256(BytesLib.pad64(_publicKey));
        StakingContractStorageLib.WithdrawersSlot storage withdrawers = StakingContractStorageLib.getWithdrawers();

        if (withdrawers.value[pubkeyRoot] != msg.sender) {
            revert Unauthorized();
        }

        emit ChangedWithdrawer(_publicKey, _newWithdrawer);

        withdrawers.value[pubkeyRoot] = _newWithdrawer;
    }

    /// @notice Set operator staking limits
    /// @dev Only callable by admin
    /// @dev Limit should not exceed the validator key count of the operator
    /// @dev Keys should be registered before limit is increased
    /// @dev Allows all keys to be verified by the system admin before limit is increased
    /// @param _operatorIndex Operator Index
    /// @param _limit New staking limit
    function setOperatorLimit(uint256 _operatorIndex, uint256 _limit) external onlyAdmin {
        StakingContractStorageLib.OperatorsSlot storage operators = StakingContractStorageLib.getOperators();
        if (operators.value[_operatorIndex].deactivated) {
            revert Deactivated();
        }
        uint256 publicKeyCount = operators.value[_operatorIndex].publicKeys.length;
        if (publicKeyCount < _limit) {
            revert OperatorLimitTooHigh(_limit, publicKeyCount);
        }
        operators.value[_operatorIndex].limit = _limit;
        _updateAvailableValidatorCount(_operatorIndex);
        emit ChangedOperatorLimit(_operatorIndex, _limit);
    }

    /// @notice Deactivates an operator and changes the fee recipient address and the staking limit
    /// @param _operatorIndex Operator Index
    /// @param _temporaryFeeRecipient Temporary address to receive funds decided by the system admin
    function deactivateOperator(uint256 _operatorIndex, address _temporaryFeeRecipient) external onlyAdmin {
        StakingContractStorageLib.OperatorsSlot storage operators = StakingContractStorageLib.getOperators();
        operators.value[_operatorIndex].limit = 0;
        emit ChangedOperatorLimit(_operatorIndex, 0);
        operators.value[_operatorIndex].deactivated = true;
        emit DeactivatedOperator(_operatorIndex);
        operators.value[_operatorIndex].feeRecipient = _temporaryFeeRecipient;
        emit ChangedOperatorAddresses(_operatorIndex, operators.value[_operatorIndex].operator, _temporaryFeeRecipient);
        _updateAvailableValidatorCount(_operatorIndex);
    }

    /// @notice Activates an operator, without changing its 0 staking limit
    /// @param _operatorIndex Operator Index
    /// @param _newFeeRecipient Sets the fee recipient address
    function activateOperator(uint256 _operatorIndex, address _newFeeRecipient) external onlyAdmin {
        StakingContractStorageLib.OperatorsSlot storage operators = StakingContractStorageLib.getOperators();
        operators.value[_operatorIndex].deactivated = false;
        emit ActivatedOperator(_operatorIndex);
        operators.value[_operatorIndex].feeRecipient = _newFeeRecipient;
        emit ChangedOperatorAddresses(_operatorIndex, operators.value[_operatorIndex].operator, _newFeeRecipient);
    }

    /// @notice Change the Operator fee
    /// @param _operatorFee Fee in Basis Point
    function setOperatorFee(uint256 _operatorFee) external onlyAdmin {
        if (_operatorFee > StakingContractStorageLib.getOperatorCommissionLimit()) {
            revert InvalidFee();
        }
        StakingContractStorageLib.setOperatorFee(_operatorFee);
        emit ChangedOperatorFee(_operatorFee);
    }

    /// @notice Change the Global fee
    /// @param _globalFee Fee in Basis Point
    function setGlobalFee(uint256 _globalFee) external onlyAdmin {
        if (_globalFee > StakingContractStorageLib.getGlobalCommissionLimit()) {
            revert InvalidFee();
        }
        StakingContractStorageLib.setGlobalFee(_globalFee);
        emit ChangedGlobalFee(_globalFee);
    }

    /// @notice Add new validator public keys and signatures
    /// @dev Only callable by operator
    /// @param _operatorIndex Operator Index
    /// @param _keyCount Number of keys added
    /// @param _publicKeys Concatenated _keyCount public keys
    /// @param _signatures Concatenated _keyCount signatures
    function addValidators(
        uint256 _operatorIndex,
        uint256 _keyCount,
        bytes calldata _publicKeys,
        bytes calldata _signatures
    ) external onlyActiveOperator(_operatorIndex) {
        if (_keyCount == 0) {
            revert InvalidArgument();
        }

        if (_publicKeys.length % PUBLIC_KEY_LENGTH != 0 || _publicKeys.length / PUBLIC_KEY_LENGTH != _keyCount) {
            revert InvalidPublicKeys();
        }

        if (_signatures.length % SIGNATURE_LENGTH != 0 || _signatures.length / SIGNATURE_LENGTH != _keyCount) {
            revert InvalidSignatures();
        }

        StakingContractStorageLib.OperatorsSlot storage operators = StakingContractStorageLib.getOperators();
        StakingContractStorageLib.OperatorIndexPerValidatorSlot
            storage operatorIndexPerValidator = StakingContractStorageLib.getOperatorIndexPerValidator();

        for (uint256 i; i < _keyCount; ) {
            bytes memory publicKey = BytesLib.slice(_publicKeys, i * PUBLIC_KEY_LENGTH, PUBLIC_KEY_LENGTH);
            bytes memory signature = BytesLib.slice(_signatures, i * SIGNATURE_LENGTH, SIGNATURE_LENGTH);

            operators.value[_operatorIndex].publicKeys.push(publicKey);
            operators.value[_operatorIndex].signatures.push(signature);

            bytes32 pubKeyRoot = _getPubKeyRoot(publicKey);

            if (operatorIndexPerValidator.value[pubKeyRoot].enabled) {
                revert DuplicateValidatorKey(publicKey);
            }

            operatorIndexPerValidator.value[pubKeyRoot] = StakingContractStorageLib.OperatorIndex({
                enabled: true,
                operatorIndex: uint32(_operatorIndex)
            });

            unchecked {
                ++i;
            }
        }

        emit ValidatorKeysAdded(_operatorIndex, _publicKeys, _signatures);

        _updateAvailableValidatorCount(_operatorIndex);
    }

    /// @notice Remove unfunded validators
    /// @dev Only callable by operator
    /// @dev Indexes should be provided in decreasing order
    /// @dev The limit will be set to the lowest removed operator index to ensure all changes above the
    ///      lowest removed validator key are verified by the system administrator
    /// @param _operatorIndex Operator Index
    /// @param _indexes List of indexes to delete, in decreasing order
    function removeValidators(uint256 _operatorIndex, uint256[] calldata _indexes)
        external
        onlyActiveOperatorOrAdmin(_operatorIndex)
    {
        if (_indexes.length == 0) {
            revert InvalidArgument();
        }

        StakingContractStorageLib.ValidatorsFundingInfo memory operatorInfo = StakingContractStorageLib
            .getValidatorsFundingInfo(_operatorIndex);
        StakingContractStorageLib.OperatorsSlot storage operators = StakingContractStorageLib.getOperators();

        if (_indexes[_indexes.length - 1] < operatorInfo.funded) {
            revert FundedValidatorDeletionAttempt();
        }
        for (uint256 i; i < _indexes.length; ) {
            if (i > 0 && _indexes[i] >= _indexes[i - 1]) {
                revert UnsortedIndexes();
            }

            emit ValidatorKeyRemoved(_operatorIndex, operators.value[_operatorIndex].publicKeys[_indexes[i]]);
            if (_indexes[i] == operators.value[_operatorIndex].publicKeys.length - 1) {
                operators.value[_operatorIndex].publicKeys.pop();
                operators.value[_operatorIndex].signatures.pop();
            } else {
                operators.value[_operatorIndex].publicKeys[_indexes[i]] = operators.value[_operatorIndex].publicKeys[
                    operators.value[_operatorIndex].publicKeys.length - 1
                ];
                operators.value[_operatorIndex].publicKeys.pop();
                operators.value[_operatorIndex].signatures[_indexes[i]] = operators.value[_operatorIndex].signatures[
                    operators.value[_operatorIndex].signatures.length - 1
                ];
                operators.value[_operatorIndex].signatures.pop();
            }

            unchecked {
                ++i;
            }
        }

        if (_indexes[_indexes.length - 1] < operators.value[_operatorIndex].limit) {
            operators.value[_operatorIndex].limit = _indexes[_indexes.length - 1];
            emit ChangedOperatorLimit(_operatorIndex, _indexes[_indexes.length - 1]);
        }

        _updateAvailableValidatorCount(_operatorIndex);
    }

    /// @notice Withdraw the Execution Layer Fee for given validators public keys
    /// @dev Funds are sent to the withdrawer account
    /// @dev This method is public on purpose
    /// @param _publicKeys Validators to withdraw Execution Layer Fees from
    function batchWithdrawELFee(bytes calldata _publicKeys) external {
        if (_publicKeys.length % PUBLIC_KEY_LENGTH != 0) {
            revert InvalidPublicKeys();
        }
        for (uint256 i = 0; i < _publicKeys.length; ) {
            bytes memory publicKey = BytesLib.slice(_publicKeys, i, PUBLIC_KEY_LENGTH);
            _onlyWithdrawerOrAdmin(publicKey);
            _deployAndWithdraw(publicKey, EXECUTION_LAYER_SALT_PREFIX, StakingContractStorageLib.getELDispatcher());
            unchecked {
                i += PUBLIC_KEY_LENGTH;
            }
        }
    }

    /// @notice Withdraw the Consensus Layer Fee for given validators public keys
    /// @dev Funds are sent to the withdrawer account
    /// @dev This method is public on purpose
    /// @param _publicKeys Validators to withdraw Consensus Layer Fees from
    function batchWithdrawCLFee(bytes calldata _publicKeys) external {
        if (_publicKeys.length % PUBLIC_KEY_LENGTH != 0) {
            revert InvalidPublicKeys();
        }
        for (uint256 i = 0; i < _publicKeys.length; ) {
            bytes memory publicKey = BytesLib.slice(_publicKeys, i, PUBLIC_KEY_LENGTH);
            _onlyWithdrawerOrAdmin(publicKey);
            _deployAndWithdraw(publicKey, CONSENSUS_LAYER_SALT_PREFIX, StakingContractStorageLib.getCLDispatcher());
            unchecked {
                i += PUBLIC_KEY_LENGTH;
            }
        }
    }

    /// @notice Withdraw both Consensus and Execution Layer Fees for given validators public keys
    /// @dev Funds are sent to the withdrawer account
    /// @param _publicKeys Validators to withdraw fees from
    function batchWithdraw(bytes calldata _publicKeys) external {
        if (_publicKeys.length % PUBLIC_KEY_LENGTH != 0) {
            revert InvalidPublicKeys();
        }
        for (uint256 i = 0; i < _publicKeys.length; ) {
            bytes memory publicKey = BytesLib.slice(_publicKeys, i, PUBLIC_KEY_LENGTH);
            _onlyWithdrawerOrAdmin(publicKey);
            _deployAndWithdraw(publicKey, EXECUTION_LAYER_SALT_PREFIX, StakingContractStorageLib.getELDispatcher());
            _deployAndWithdraw(publicKey, CONSENSUS_LAYER_SALT_PREFIX, StakingContractStorageLib.getCLDispatcher());
            unchecked {
                i += PUBLIC_KEY_LENGTH;
            }
        }
    }

    /// @notice Withdraw the Execution Layer Fee for a given validator public key
    /// @dev Funds are sent to the withdrawer account
    /// @param _publicKey Validator to withdraw Execution Layer Fees from
    function withdrawELFee(bytes calldata _publicKey) external {
        _onlyWithdrawerOrAdmin(_publicKey);
        _deployAndWithdraw(_publicKey, EXECUTION_LAYER_SALT_PREFIX, StakingContractStorageLib.getELDispatcher());
    }

    /// @notice Withdraw the Consensus Layer Fee for a given validator public key
    /// @dev Funds are sent to the withdrawer account
    /// @param _publicKey Validator to withdraw Consensus Layer Fees from
    function withdrawCLFee(bytes calldata _publicKey) external {
        _onlyWithdrawerOrAdmin(_publicKey);
        _deployAndWithdraw(_publicKey, CONSENSUS_LAYER_SALT_PREFIX, StakingContractStorageLib.getCLDispatcher());
    }

    /// @notice Withdraw both Consensus and Execution Layer Fee for a given validator public key
    /// @dev Reverts if any is null
    /// @param _publicKey Validator to withdraw Execution and Consensus Layer Fees from
    function withdraw(bytes calldata _publicKey) external {
        _onlyWithdrawerOrAdmin(_publicKey);
        _deployAndWithdraw(_publicKey, EXECUTION_LAYER_SALT_PREFIX, StakingContractStorageLib.getELDispatcher());
        _deployAndWithdraw(_publicKey, CONSENSUS_LAYER_SALT_PREFIX, StakingContractStorageLib.getCLDispatcher());
    }

    function requestValidatorsExit(bytes calldata _publicKeys) external {
        if (_publicKeys.length % PUBLIC_KEY_LENGTH != 0) {
            revert InvalidPublicKeys();
        }
        for (uint256 i = 0; i < _publicKeys.length; ) {
            bytes memory publicKey = BytesLib.slice(_publicKeys, i, PUBLIC_KEY_LENGTH);
            bytes32 pubKeyRoot = _getPubKeyRoot(publicKey);
            address withdrawer = _getWithdrawer(pubKeyRoot);
            if (msg.sender != withdrawer) {
                revert Unauthorized();
            }
            _setExitRequest(pubKeyRoot, true);
            emit ExitRequest(withdrawer, publicKey);
            unchecked {
                i += PUBLIC_KEY_LENGTH;
            }
        }
    }

    /// @notice Utility to stop or allow deposits
    function setDepositsStopped(bool val) external onlyAdmin {
        emit ChangedDepositsStopped(val);
        StakingContractStorageLib.setDepositStopped(val);
    }

    /// ██ ███    ██ ████████ ███████ ██████  ███    ██  █████  ██
    /// ██ ████   ██    ██    ██      ██   ██ ████   ██ ██   ██ ██
    /// ██ ██ ██  ██    ██    █████   ██████  ██ ██  ██ ███████ ██
    /// ██ ██  ██ ██    ██    ██      ██   ██ ██  ██ ██ ██   ██ ██
    /// ██ ██   ████    ██    ███████ ██   ██ ██   ████ ██   ██ ███████

    function _onlyWithdrawerOrAdmin(bytes memory _publicKey) internal view {
        if (
            msg.sender != _getWithdrawer(_getPubKeyRoot(_publicKey)) &&
            StakingContractStorageLib.getAdmin() != msg.sender
        ) {
            revert InvalidWithdrawer();
        }
    }

    function _onlyActiveOperator(uint256 _operatorIndex) internal view {
        StakingContractStorageLib.OperatorInfo storage operatorInfo = StakingContractStorageLib.getOperators().value[
            _operatorIndex
        ];

        if (operatorInfo.deactivated) {
            revert Deactivated();
        }

        if (msg.sender != operatorInfo.operator) {
            revert Unauthorized();
        }
    }

    function _getPubKeyRoot(bytes memory _publicKey) internal pure returns (bytes32) {
        return sha256(BytesLib.pad64(_publicKey));
    }

    function _getWithdrawer(bytes32 _publicKeyRoot) internal view returns (address) {
        return StakingContractStorageLib.getWithdrawers().value[_publicKeyRoot];
    }

    function _getExitRequest(bytes32 _publicKeyRoot) internal view returns (bool) {
        return StakingContractStorageLib.getExitRequestMap().value[_publicKeyRoot];
    }

    function _setExitRequest(bytes32 _publicKeyRoot, bool _value) internal {
        StakingContractStorageLib.getExitRequestMap().value[_publicKeyRoot] = _value;
    }

    function _updateAvailableValidatorCount(uint256 _operatorIndex) internal {
        StakingContractStorageLib.ValidatorsFundingInfo memory validatorFundingInfo = StakingContractStorageLib
            .getValidatorsFundingInfo(_operatorIndex);
        StakingContractStorageLib.OperatorsSlot storage operators = StakingContractStorageLib.getOperators();

        uint32 oldAvailableCount = validatorFundingInfo.availableKeys;
        uint32 newAvailableCount = 0;
        uint256 cap = _min(operators.value[_operatorIndex].limit, operators.value[_operatorIndex].publicKeys.length);

        if (cap <= validatorFundingInfo.funded) {
            StakingContractStorageLib.setValidatorsFundingInfo(_operatorIndex, 0, validatorFundingInfo.funded);
        } else {
            newAvailableCount = uint32(cap - validatorFundingInfo.funded);
            StakingContractStorageLib.setValidatorsFundingInfo(
                _operatorIndex,
                newAvailableCount,
                validatorFundingInfo.funded
            );
        }

        if (oldAvailableCount != newAvailableCount) {
            StakingContractStorageLib.setTotalAvailableValidators(
                (StakingContractStorageLib.getTotalAvailableValidators() - oldAvailableCount) + newAvailableCount
            );
        }
    }

    function _addressToWithdrawalCredentials(address _recipient) internal pure returns (bytes32) {
        return
            bytes32(uint256(uint160(_recipient)) + 0x0100000000000000000000000000000000000000000000000000000000000000);
    }

    function _depositValidatorsOfOperator(
        uint256 _operatorIndex,
        uint256 _validatorCount,
        address _withdrawer
    ) internal {
        StakingContractStorageLib.OperatorsSlot storage operators = StakingContractStorageLib.getOperators();
        StakingContractStorageLib.OperatorInfo storage operator = operators.value[_operatorIndex];
        StakingContractStorageLib.ValidatorsFundingInfo memory vfi = StakingContractStorageLib.getValidatorsFundingInfo(
            _operatorIndex
        );

        for (uint256 i = vfi.funded; i < vfi.funded + _validatorCount; ) {
            bytes memory publicKey = operator.publicKeys[i];
            bytes memory signature = operator.signatures[i];
            address consensusLayerRecipient = _getDeterministicReceiver(publicKey, CONSENSUS_LAYER_SALT_PREFIX);
            bytes32 withdrawalCredentials = _addressToWithdrawalCredentials(consensusLayerRecipient);
            _depositValidator(publicKey, signature, withdrawalCredentials);
            bytes32 pubkeyRoot = _getPubKeyRoot(publicKey);
            StakingContractStorageLib.getWithdrawers().value[pubkeyRoot] = _withdrawer;
            emit Deposit(msg.sender, _withdrawer, publicKey, signature);
            unchecked {
                ++i;
            }
        }

        StakingContractStorageLib.setValidatorsFundingInfo(
            _operatorIndex,
            uint32(vfi.availableKeys - _validatorCount),
            uint32(vfi.funded + _validatorCount)
        );
    }

    /// @notice Internal utility to deposit a public key, its signature and 32 ETH to the consensus layer
    /// @param _publicKey The Public Key to deposit
    /// @param _signature The Signature to deposit
    /// @param _withdrawalCredentials The Withdrawal Credentials to deposit
    function _depositValidator(
        bytes memory _publicKey,
        bytes memory _signature,
        bytes32 _withdrawalCredentials
    ) internal {
        bytes32 pubkeyRoot = _getPubKeyRoot(_publicKey);
        bytes32 signatureRoot = sha256(
            abi.encodePacked(
                sha256(BytesLib.slice(_signature, 0, 64)),
                sha256(BytesLib.pad64(BytesLib.slice(_signature, 64, SIGNATURE_LENGTH - 64)))
            )
        );

        uint256 depositAmount = DEPOSIT_SIZE / 1000000000 wei;

        bytes32 depositDataRoot = sha256(
            abi.encodePacked(
                sha256(abi.encodePacked(pubkeyRoot, _withdrawalCredentials)),
                sha256(abi.encodePacked(Uint256Lib.toLittleEndian64(depositAmount), signatureRoot))
            )
        );

        uint256 targetBalance = address(this).balance - DEPOSIT_SIZE;

        IDepositContract(StakingContractStorageLib.getDepositContract()).deposit{value: DEPOSIT_SIZE}(
            _publicKey,
            abi.encodePacked(_withdrawalCredentials),
            _signature,
            depositDataRoot
        );

        if (address(this).balance != targetBalance) {
            revert DepositFailure();
        }
    }

    function _depositOnOneOperator(
        address _withdrawer,
        uint256 _depositCount,
        uint256 _totalAvailableValidators
    ) internal {
        _depositValidatorsOfOperator(0, _depositCount, _withdrawer);
        StakingContractStorageLib.setTotalAvailableValidators(_totalAvailableValidators - _depositCount);
    }

    function _deposit(address _withdrawer) internal {
        if (StakingContractStorageLib.getDepositStopped()) {
            revert DepositsStopped();
        }
        if (msg.value == 0 || msg.value % DEPOSIT_SIZE != 0) {
            revert InvalidDepositValue();
        }
        uint256 totalAvailableValidators = StakingContractStorageLib.getTotalAvailableValidators();
        uint256 depositCount = msg.value / DEPOSIT_SIZE;
        if (depositCount > totalAvailableValidators) {
            revert NotEnoughValidators();
        }
        StakingContractStorageLib.OperatorsSlot storage operators = StakingContractStorageLib.getOperators();
        if (operators.value.length == 0) {
            revert NoOperators();
        }
        _depositOnOneOperator(_withdrawer, depositCount, totalAvailableValidators);
    }

    function _min(uint256 _a, uint256 _b) internal pure returns (uint256) {
        if (_a < _b) {
            return _a;
        }
        return _b;
    }

    /// @notice Internal utility to compute the receiver deterministic address
    /// @param _publicKey Public Key assigned to the receiver
    /// @param _prefix Prefix used to generate multiple receivers per public key
    function _getDeterministicReceiver(bytes memory _publicKey, uint256 _prefix) internal view returns (address) {
        bytes32 publicKeyRoot = _getPubKeyRoot(_publicKey);
        bytes32 salt = sha256(abi.encodePacked(_prefix, publicKeyRoot));
        address implementation = StakingContractStorageLib.getFeeRecipientImplementation();
        return Clones.predictDeterministicAddress(implementation, salt);
    }

    /// @notice Internal utility to deploy and withdraw the fees from a receiver
    /// @param _publicKey Public Key assigned to the receiver
    /// @param _prefix Prefix used to generate multiple receivers per public key
    /// @param _dispatcher Address of the dispatcher contract
    function _deployAndWithdraw(
        bytes memory _publicKey,
        uint256 _prefix,
        address _dispatcher
    ) internal {
        bytes32 publicKeyRoot = _getPubKeyRoot(_publicKey);
        bytes32 feeRecipientSalt = sha256(abi.encodePacked(_prefix, publicKeyRoot));
        address implementation = StakingContractStorageLib.getFeeRecipientImplementation();
        address feeRecipientAddress = Clones.predictDeterministicAddress(implementation, feeRecipientSalt);
        if (feeRecipientAddress.code.length == 0) {
            Clones.cloneDeterministic(implementation, feeRecipientSalt);
            IFeeRecipient(feeRecipientAddress).init(_dispatcher, publicKeyRoot);
        }
        IFeeRecipient(feeRecipientAddress).withdraw();
    }
}
