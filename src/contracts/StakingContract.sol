//SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.10;

import "./libs/StakingContractStorageLib.sol";
import "./libs/UintLib.sol";
import "./libs/BytesLib.sol";

import "./interfaces/IDepositContract.sol";
import "./interfaces/IFeeRecipient.sol";

import "@openzeppelin/contracts/proxy/Clones.sol";

/// @title Ethereum Staking Contract
/// @author Kiln
/// @notice You can use this contract to store validator keys and have users fund them and trigger deposits.
contract StakingContract {
    using StakingContractStorageLib for bytes32;

    bytes32 internal constant ADMIN_SLOT =
        /* keccak256("StakingContract.admin") */
        hex"fbeda9bc03875013b12a1ec161efb8e5bf7e58e3cec96a1ea9efd3e264d26e64";
    bytes32 internal constant VERSION_SLOT =
        /* keccak256("StakingContract.version") */
        hex"d5c553085b8382c47128ae7612257fd5dc3b4fc4d3a108925604d3c8700c025b";
    bytes32 internal constant OPERATOR_SLOT =
        /* keccak256("StakingContract.operator") */
        hex"dfe7334ae89a4aa54c085540947bfa7e13e6b6933be4c49f359d18e88c0dbde5";
    bytes32 internal constant SIGNATURES_SLOT =
        /* keccak256("StakingContract.signatures") */
        hex"2805e4a7c8c139ac2ebe63141d90c488245fd479906b2c60bd42603b8a2ca08b";
    bytes32 internal constant PUBLIC_KEYS_SLOT =
        /* keccak256("StakingContract.publicKeys") */
        hex"cc0b8384259c4a4e6418cdc72955757e9214822019f44d8b5283077c1b46d43c";
    bytes32 internal constant WITHDRAWERS_SLOT =
        /* keccak256("StakingContract.withdrawers") */
        hex"86647fdbbdb534026d3e0f93a551cecf651c2b40fcdfef4b9fd9ed826133e265";
    bytes32 internal constant VALIDATORS_COUNT_SLOT =
        /* keccak256("StakingContract.validatorsCount") */
        hex"e9622dd0bba60226e1dbc661ca8aae56cc90dc7e9b3f33ece002f6764b3801b8";
    bytes32 internal constant DEPOSIT_CONTRACT_SLOT =
        /* keccak256("StakingContract.depositContract") */
        hex"bc8b9852d17d50256bb221fdf6ee12d78dd493d807e907f7d223c40d65abd6b9";
    bytes32 internal constant WITHDRAWAL_CREDENTIALS_SLOT =
        /* keccak256("StakingContract.withdrawalCredentials") */
        hex"2783da738595cd6ebaec6fd0f06d62f2266a9e475e2d1feb1d26aa2d1e051255";
    bytes32 internal constant EL_FEE_SLOT = keccak256("StakingContract.executionLayerFee");
    bytes32 internal constant EL_FEE_RECIPIENT_IMPLEMENTATION_SLOT =
        keccak256("StakingContract.executionLayerFeeRecipientImplementation");
    bytes32 internal constant CL_FEE_SLOT = keccak256("StakingContract.consensusLayerFee");
    bytes32 internal constant CL_FEE_RECIPIENT_IMPLEMENTATION_SLOT =
        keccak256("StakingContract.consensusLayerFeeRecipientImplementation");

    uint256 internal constant EXECUTION_LAYER_CODE = 0;
    uint256 internal constant CONSENSUS_LAYER_CODE = 1;
    uint256 public constant SIGNATURE_LENGTH = 96;
    uint256 public constant PUBLIC_KEY_LENGTH = 48;
    uint256 public constant DEPOSIT_SIZE = 32 ether;
    uint256 internal constant BASIS_POINTS = 10_000;

    error InvalidCall();
    error Unauthorized();
    error InvalidFee();
    error NotEnoughKeys();
    error DepositFailure();
    error InvalidArgument();
    error UnsortedIndexes();
    error InvalidPublicKeys();
    error InvalidSignatures();
    error AlreadyInitialized();
    error InvalidMessageValue();
    error FundedValidatorDeletionAttempt();

    event Deposit(address indexed caller, address indexed withdrawer, bytes publicKey, bytes32 publicKeyRoot);

    /// @notice Ensures an initialisation call has been called only once per _version value
    /// @param _version The current initialisation value
    modifier init(uint256 _version) {
        if (_version != VERSION_SLOT.getUint256() + 1) {
            revert AlreadyInitialized();
        }

        VERSION_SLOT.setUint256(_version);

        _;
    }

    /// @notice Ensures that the caller is the operator
    modifier onlyOperator() {
        if (msg.sender != OPERATOR_SLOT.getAddress()) {
            revert Unauthorized();
        }

        _;
    }

    /// @notice Ensures that the caller is the admin
    modifier onlyAdmin() {
        if (msg.sender != ADMIN_SLOT.getAddress()) {
            revert Unauthorized();
        }

        _;
    }

    /// @notice Ensures that the caller is the operator or the admin
    modifier onlyAdminOrOperator() {
        if (msg.sender != ADMIN_SLOT.getAddress() && msg.sender != OPERATOR_SLOT.getAddress()) {
            revert Unauthorized();
        }

        _;
    }

    /// @notice Initializes version 1 of Staking Contract
    /// @param _operator Address of the operator allowed to add/remove keys
    /// @param _admin Address of the admin allowed to change the operator and admin
    /// @param _depositContract Address of the Deposit Contract
    /// @param _withdrawalCredentials Withdrawal Credentials to apply to all provided keys upon deposit
    function initialize_1(
        address _operator,
        address _admin,
        address _depositContract,
        address _elFeeRecipientImplementation,
        address _clFeeRecipientImplementation,
        bytes32 _withdrawalCredentials,
        uint256 _elFee,
        uint256 _clFee
    ) external init(1) {
        OPERATOR_SLOT.setAddress(_operator);
        DEPOSIT_CONTRACT_SLOT.setAddress(_depositContract);
        WITHDRAWAL_CREDENTIALS_SLOT.setBytes32(_withdrawalCredentials);
        ADMIN_SLOT.setAddress(_admin);

        EL_FEE_RECIPIENT_IMPLEMENTATION_SLOT.setAddress(_elFeeRecipientImplementation);
        EL_FEE_SLOT.setUint256(_elFee);

        CL_FEE_RECIPIENT_IMPLEMENTATION_SLOT.setAddress(_clFeeRecipientImplementation);
        CL_FEE_SLOT.setUint256(_clFee);
    }

    /// @notice Retrieve the admin address
    function getAdmin() external view returns (address) {
        return ADMIN_SLOT.getAddress();
    }

    /// @notice Retrieve the operator address
    function getOperator() external view returns (address) {
        return OPERATOR_SLOT.getAddress();
    }

    /// @notice Change the Execution Layer Fee taken by the node operator
    /// @param _fee Fee in Basis Point
    function setELFee(uint256 _fee) external onlyAdmin {
        if (_fee > BASIS_POINTS) {
            revert InvalidFee();
        }
        EL_FEE_SLOT.setUint256(_fee);
    }

    /// @notice Change the Consensus Layer Fee taken by the node operator
    /// @param _fee Fee in Basis Point
    function setCLFee(uint256 _fee) external onlyAdmin {
        if (_fee > BASIS_POINTS) {
            revert InvalidFee();
        }
        CL_FEE_SLOT.setUint256(_fee);
    }

    /// @notice Retrieve the Execution Layer Fee taken by the node operator
    function getELFee() external view returns (uint256) {
        return EL_FEE_SLOT.getUint256();
    }

    /// @notice Retrieve the Consensus Layer Fee taken by the node operator
    function getCLFee() external view returns (uint256) {
        return CL_FEE_SLOT.getUint256();
    }

    /// @notice Retrieve the Execution & Consensus Layer Fee operator recipient for a given public key
    function getFeeTreasury(bytes32) external view returns (address) {
        return OPERATOR_SLOT.getAddress();
    }

    /// @notice Retrieve the withdrawer for a specific public key
    /// @param _publicKey Public Key to retrieve the withdrawer
    function getWithdrawer(bytes memory _publicKey) external view returns (address) {
        bytes32 pubkeyRoot = sha256(BytesLib.pad64(_publicKey));
        return WITHDRAWERS_SLOT.getStorageBytes32ToAddressMapping().value[pubkeyRoot];
    }

    /// @notice Retrieve the withdrawer for a specific public key
    /// @param _publicKeyRoot Public Key to retrieve the withdrawer
    function getWithdrawerFromPublicKeyRoot(bytes32 _publicKeyRoot) external view returns (address) {
        return WITHDRAWERS_SLOT.getStorageBytes32ToAddressMapping().value[_publicKeyRoot];
    }

    /// @notice Retrieve the amount of funded validators
    function fundedValidatorsCount() external view returns (uint256) {
        return VALIDATORS_COUNT_SLOT.getUint256();
    }

    /// @notice Retrieve the amount of registered validators (funded + not yet funded)
    function totalValidatorCount() external view returns (uint256) {
        return PUBLIC_KEYS_SLOT.getStorageBytesArray().value.length;
    }

    /// @notice Retrieve the details of a validator
    /// @param _idx Index of the validator
    function getValidator(uint256 _idx)
        external
        view
        returns (
            bytes memory publicKey,
            bytes memory signature,
            address withdrawer,
            bool funded
        )
    {
        StakingContractStorageLib.BytesArraySlot storage publicKeysStore = PUBLIC_KEYS_SLOT.getStorageBytesArray();
        StakingContractStorageLib.BytesArraySlot storage signaturesStore = SIGNATURES_SLOT.getStorageBytesArray();
        StakingContractStorageLib.Bytes32ToAddressMappingSlot storage withdrawers = WITHDRAWERS_SLOT
            .getStorageBytes32ToAddressMapping();
        uint256 validatorCount = VALIDATORS_COUNT_SLOT.getUint256();

        publicKey = publicKeysStore.value[_idx];
        signature = signaturesStore.value[_idx];
        withdrawer = withdrawers.value[sha256(BytesLib.pad64(publicKey))];
        funded = _idx < validatorCount;
    }

    /// @notice Change the admin address
    /// @dev Only the admin is allowed to call this method
    /// @param _newAdmin New Admin address
    function setAdmin(address _newAdmin) external onlyAdmin {
        ADMIN_SLOT.setAddress(_newAdmin);
    }

    /// @notice Change the operator address
    /// @dev Only the admin or the operator are allowed to call this method
    /// @param _newOperator New Operator address
    function setOperator(address _newOperator) external onlyAdminOrOperator {
        OPERATOR_SLOT.setAddress(_newOperator);
    }

    /// @notice Change the withdrawer for a specific public key
    /// @dev Only the previous withdrawer of the public key can change the withdrawer
    /// @param _publicKey The public key to change
    /// @param _newWithdrawer The new withdrawer address
    function setWithdrawer(bytes calldata _publicKey, address _newWithdrawer) external {
        bytes32 pubkeyRoot = sha256(BytesLib.pad64(_publicKey));
        StakingContractStorageLib.Bytes32ToAddressMappingSlot storage publicKeyOwnership = WITHDRAWERS_SLOT
            .getStorageBytes32ToAddressMapping();

        if (msg.sender != publicKeyOwnership.value[pubkeyRoot]) {
            revert Unauthorized();
        }

        publicKeyOwnership.value[pubkeyRoot] = _newWithdrawer;
    }

    /// @notice Explicit deposit method
    /// @dev A multiple of 32 ETH should be sent
    /// @param _withdrawer The withdrawer address
    function deposit(address _withdrawer) external payable {
        _deposit(_withdrawer);
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

    /// @notice Register new validators
    /// @dev Only the operator or the admin are allowed to call this method
    /// @dev publickKeys is the concatenation of keyCount public keys
    /// @dev signatures is the concatenation of keyCount signatures
    /// @param keyCount The expected number of keys from publicKeys and signatures
    /// @param publicKeys Concatenated public keys
    /// @param signatures Concatenated signatures
    function registerValidators(
        uint256 keyCount,
        bytes calldata publicKeys,
        bytes calldata signatures
    ) external onlyAdminOrOperator {
        if (keyCount == 0) {
            revert InvalidArgument();
        }

        if (publicKeys.length % PUBLIC_KEY_LENGTH != 0 || publicKeys.length / PUBLIC_KEY_LENGTH != keyCount) {
            revert InvalidPublicKeys();
        }

        if (signatures.length % SIGNATURE_LENGTH != 0 || signatures.length / SIGNATURE_LENGTH != keyCount) {
            revert InvalidSignatures();
        }

        StakingContractStorageLib.BytesArraySlot storage publicKeysStore = PUBLIC_KEYS_SLOT.getStorageBytesArray();
        StakingContractStorageLib.BytesArraySlot storage signaturesStore = SIGNATURES_SLOT.getStorageBytesArray();

        for (uint256 i; i < keyCount; ) {
            bytes memory publicKey = BytesLib.slice(publicKeys, i * PUBLIC_KEY_LENGTH, PUBLIC_KEY_LENGTH);
            bytes memory signature = BytesLib.slice(signatures, i * SIGNATURE_LENGTH, SIGNATURE_LENGTH);

            publicKeysStore.value.push(publicKey);
            signaturesStore.value.push(signature);

            unchecked {
                ++i;
            }
        }
    }

    /// @notice Remove validators
    /// @dev Only the operator or the admin are allowed to call this method
    /// @dev The indexes to delete should all be greater than the amount of funded validators
    /// @dev The indexes to delete should be sorted in descending order or the method will fail
    /// @param _indexes The indexes to delete
    function removeValidators(uint256[] calldata _indexes) external onlyAdminOrOperator {
        if (_indexes.length == 0) {
            revert InvalidArgument();
        }

        uint256 validatorsCount = VALIDATORS_COUNT_SLOT.getUint256();
        StakingContractStorageLib.BytesArraySlot storage publicKeysStore = PUBLIC_KEYS_SLOT.getStorageBytesArray();
        StakingContractStorageLib.BytesArraySlot storage signaturesStore = SIGNATURES_SLOT.getStorageBytesArray();

        for (uint256 i; i < _indexes.length; ) {
            if (i > 0 && _indexes[i] >= _indexes[i - 1]) {
                revert UnsortedIndexes();
            }

            if (_indexes[i] < validatorsCount) {
                revert FundedValidatorDeletionAttempt();
            }

            if (_indexes[i] == publicKeysStore.value.length - 1) {
                publicKeysStore.value.pop();
                signaturesStore.value.pop();
            } else {
                publicKeysStore.value[_indexes[i]] = publicKeysStore.value[publicKeysStore.value.length - 1];
                publicKeysStore.value.pop();
                signaturesStore.value[_indexes[i]] = signaturesStore.value[signaturesStore.value.length - 1];
                signaturesStore.value.pop();
            }

            unchecked {
                ++i;
            }
        }
    }

    /// @notice Withdraw the Execution Layer Fee for a given validator public key
    /// @dev Funds are sent to the withdrawer account
    /// @dev This method is public on purpose
    /// @param _publicKey Validator to withdraw Execution Layer Fees from
    function withdrawELFee(bytes calldata _publicKey) external {
        _deployAndWithdrawELFee(_publicKey);
    }

    /// @notice Withdraw the Consensus Layer Fee for a given validator public key
    /// @dev Funds are sent to the withdrawer account
    /// @dev This method is public on purpose
    /// @param _publicKey Validator to withdraw Consensus Layer Fees from
    function withdrawCLFee(bytes calldata _publicKey) external {
        _deployAndWithdrawCLFee(_publicKey);
    }

    /// @notice Compute the Execution Layer Fee recipient address for a given validator public key
    /// @param _publicKey Validator to get the recipient
    function getELFeeRecipient(bytes calldata _publicKey) external view returns (address) {
        return _getDeterministicELFeeRecipientAddress(_publicKey);
    }

    /// @notice Compute the Consensus Layer Fee recipient address for a given validator public key
    /// @param _publicKey Validator to get the recipient
    function getCLFeeRecipient(bytes calldata _publicKey) external view returns (address) {
        return _getDeterministicCLFeeRecipientAddress(_publicKey);
    }

    /// @notice Withdraw both Consensus and Execution Layer Fee for a given validator public key
    /// @dev Reverts if any is null
    /// @param _publicKey Validator to withdraw Execution and Consensus Layer Fees from
    function withdraw(bytes calldata _publicKey) external {
        _deployAndWithdrawELFee(_publicKey);
        _deployAndWithdrawCLFee(_publicKey);
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
        bytes32 pubkeyRoot = sha256(BytesLib.pad64(_publicKey));
        bytes32 signatureRoot = sha256(
            abi.encodePacked(
                sha256(BytesLib.slice(_signature, 0, 64)),
                sha256(BytesLib.pad64(BytesLib.slice(_signature, 64, SIGNATURE_LENGTH - 64)))
            )
        );

        uint256 depositAmount = DEPOSIT_SIZE / 1000000000 wei;
        assert(depositAmount * 1000000000 wei == DEPOSIT_SIZE);

        bytes32 depositDataRoot = sha256(
            abi.encodePacked(
                sha256(abi.encodePacked(pubkeyRoot, _withdrawalCredentials)),
                sha256(abi.encodePacked(Uint256Lib.toLittleEndian64(depositAmount), signatureRoot))
            )
        );

        uint256 targetBalance = address(this).balance - DEPOSIT_SIZE;

        IDepositContract(DEPOSIT_CONTRACT_SLOT.getAddress()).deposit{value: DEPOSIT_SIZE}(
            _publicKey,
            abi.encodePacked(_withdrawalCredentials),
            _signature,
            depositDataRoot
        );

        if (address(this).balance != targetBalance) {
            revert DepositFailure();
        }
    }

    /// @notice Perform one or multiple deposits for the same withdrawer
    /// @param _withdrawer Address allowed to withdraw the funds of the deposits
    function _deposit(address _withdrawer) internal {
        if (msg.value == 0 || msg.value % DEPOSIT_SIZE != 0) {
            revert InvalidMessageValue();
        }

        uint256 depositCount = msg.value / DEPOSIT_SIZE;
        uint256 validatorCount = VALIDATORS_COUNT_SLOT.getUint256();
        StakingContractStorageLib.BytesArraySlot storage publicKeysStore = PUBLIC_KEYS_SLOT.getStorageBytesArray();
        StakingContractStorageLib.BytesArraySlot storage signaturesStore = SIGNATURES_SLOT.getStorageBytesArray();
        bytes32 withdrawalCredentials = WITHDRAWAL_CREDENTIALS_SLOT.getBytes32();

        if (validatorCount + depositCount > publicKeysStore.value.length) {
            revert NotEnoughKeys();
        }

        StakingContractStorageLib.Bytes32ToAddressMappingSlot storage publicKeyOwnership = WITHDRAWERS_SLOT
            .getStorageBytes32ToAddressMapping();

        for (uint256 i; i < depositCount; ) {
            bytes memory publicKey = publicKeysStore.value[validatorCount + i];
            bytes32 publicKeyRoot = sha256(BytesLib.pad64(publicKey));
            _depositValidator(publicKey, signaturesStore.value[validatorCount + i], withdrawalCredentials);
            publicKeyOwnership.value[publicKeyRoot] = _withdrawer;
            emit Deposit(msg.sender, _withdrawer, publicKey, publicKeyRoot);
            unchecked {
                ++i;
            }
        }

        VALIDATORS_COUNT_SLOT.setUint256(validatorCount + depositCount);
    }

    /// @notice Computes the execution layer fee recipient for the given validator public key
    /// @param _publicKey The public key linked to the recipient
    function _getDeterministicELFeeRecipientAddress(bytes calldata _publicKey) internal view returns (address) {
        bytes32 publicKeyRoot = sha256(BytesLib.pad64(_publicKey));
        bytes32 feeRecipientSalt = sha256(abi.encodePacked(EXECUTION_LAYER_CODE, publicKeyRoot));
        address implementation = EL_FEE_RECIPIENT_IMPLEMENTATION_SLOT.getAddress();
        return Clones.predictDeterministicAddress(implementation, feeRecipientSalt);
    }

    /// @notice Computes the consensus layer fee recipient for the given validator public key
    /// @param _publicKey The public key linked to the recipient
    function _getDeterministicCLFeeRecipientAddress(bytes calldata _publicKey) internal view returns (address) {
        bytes32 publicKeyRoot = sha256(BytesLib.pad64(_publicKey));
        bytes32 feeRecipientSalt = sha256(abi.encodePacked(CONSENSUS_LAYER_CODE, publicKeyRoot));
        address implementation = CL_FEE_RECIPIENT_IMPLEMENTATION_SLOT.getAddress();
        return Clones.predictDeterministicAddress(implementation, feeRecipientSalt);
    }

    /// @notice Computes the execution layer fee recipient for the given validator public key, checks if a
    ///         contract exists at given address, creates a minimal Clone if not and then performs withdrawal
    /// @param _publicKey The public key linked to the recipient
    function _deployAndWithdrawELFee(bytes calldata _publicKey) internal {
        bytes32 publicKeyRoot = sha256(BytesLib.pad64(_publicKey));
        bytes32 feeRecipientSalt = sha256(abi.encodePacked(EXECUTION_LAYER_CODE, publicKeyRoot));
        address implementation = EL_FEE_RECIPIENT_IMPLEMENTATION_SLOT.getAddress();
        address feeRecipientAddress = Clones.predictDeterministicAddress(implementation, feeRecipientSalt);
        if (feeRecipientAddress.code.length == 0) {
            Clones.cloneDeterministic(implementation, feeRecipientSalt);
            IELFeeRecipient(feeRecipientAddress).initELFR(address(this), publicKeyRoot);
        }
        IELFeeRecipient(feeRecipientAddress).withdraw();
    }

    /// @notice Computes the consensus layer fee recipient for the given validator public key, checks if a
    ///         contract exists at given address, creates a minimal Clone if not and then performs withdrawal
    /// @param _publicKey The public key linked to the recipient
    function _deployAndWithdrawCLFee(bytes calldata _publicKey) internal {
        bytes32 publicKeyRoot = sha256(BytesLib.pad64(_publicKey));
        bytes32 feeRecipientSalt = sha256(abi.encodePacked(CONSENSUS_LAYER_CODE, publicKeyRoot));
        address implementation = CL_FEE_RECIPIENT_IMPLEMENTATION_SLOT.getAddress();
        address feeRecipientAddress = Clones.predictDeterministicAddress(implementation, feeRecipientSalt);
        if (feeRecipientAddress.code.length == 0) {
            Clones.cloneDeterministic(implementation, feeRecipientSalt);
            ICLFeeRecipient(feeRecipientAddress).initCLFR(address(this), publicKeyRoot);
        }
        ICLFeeRecipient(feeRecipientAddress).withdraw();
    }
}
