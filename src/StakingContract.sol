// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.10;

import "./libs/StateLib.sol";
import "./libs/UintLib.sol";
import "./libs/BytesLib.sol";

import "./interfaces/IDepositContract.sol";
import "./test/console.sol";

contract StakingContract {
    using StateLib for bytes32;

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

    uint256 public constant SIGNATURE_LENGTH = 96;
    uint256 public constant PUBLIC_KEY_LENGTH = 48;
    uint256 public constant DEPOSIT_SIZE = 32 ether;

    error InvalidCall();
    error Unauthorized();
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

    modifier init(uint256 _version) {
        if (_version != VERSION_SLOT.getUint256() + 1) {
            revert AlreadyInitialized();
        }

        VERSION_SLOT.setUint256(_version);

        _;
    }

    modifier onlyOperator() {
        if (msg.sender != OPERATOR_SLOT.getAddress()) {
            revert Unauthorized();
        }

        _;
    }

    function initialize_1(
        address _operator,
        address _depositContract,
        bytes32 _withdrawalCredentials
    ) external init(1) {
        OPERATOR_SLOT.setAddress(_operator);
        DEPOSIT_CONTRACT_SLOT.setAddress(_depositContract);
        WITHDRAWAL_CREDENTIALS_SLOT.setBytes32(_withdrawalCredentials);
    }

    function fundedValidatorsCount() external view returns (uint256) {
        return VALIDATORS_COUNT_SLOT.getUint256();
    }

    function totalValidatorCount() external view returns (uint256) {
        return PUBLIC_KEYS_SLOT.getStorageBytesArray().value.length;
    }

    function getWithdrawer(bytes memory _publicKey) external view returns (address) {
        bytes32 pubkeyRoot = sha256(BytesLib.pad64(_publicKey));
        StateLib.Bytes32ToAddressMappingSlot storage publicKeyOwnership = WITHDRAWERS_SLOT
            .getStorageBytes32ToAddressMapping();
        return publicKeyOwnership.value[pubkeyRoot];
    }

    function deposit(address _withdrawer) external payable {
        _deposit(_withdrawer);
    }

    receive() external payable {
        _deposit(msg.sender);
    }

    fallback() external payable {
        revert InvalidCall();
    }

    function registerValidators(
        uint256 keyCount,
        bytes calldata publicKeys,
        bytes calldata signatures
    ) external onlyOperator {
        if (keyCount == 0) {
            revert InvalidArgument();
        }

        if (publicKeys.length % PUBLIC_KEY_LENGTH != 0 || publicKeys.length / PUBLIC_KEY_LENGTH != keyCount) {
            revert InvalidPublicKeys();
        }

        if (signatures.length % SIGNATURE_LENGTH != 0 || signatures.length / SIGNATURE_LENGTH != keyCount) {
            revert InvalidSignatures();
        }

        StateLib.BytesArraySlot storage publicKeysStore = PUBLIC_KEYS_SLOT.getStorageBytesArray();
        StateLib.BytesArraySlot storage signaturesStore = SIGNATURES_SLOT.getStorageBytesArray();

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

    function removeValidators(uint256[] calldata _indexes) external onlyOperator {
        if (_indexes.length == 0) {
            revert InvalidArgument();
        }

        uint256 validatorsCount = VALIDATORS_COUNT_SLOT.getUint256();
        StateLib.BytesArraySlot storage publicKeysStore = PUBLIC_KEYS_SLOT.getStorageBytesArray();
        StateLib.BytesArraySlot storage signaturesStore = SIGNATURES_SLOT.getStorageBytesArray();

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
        StateLib.BytesArraySlot storage publicKeysStore = PUBLIC_KEYS_SLOT.getStorageBytesArray();
        StateLib.BytesArraySlot storage signaturesStore = SIGNATURES_SLOT.getStorageBytesArray();
        StateLib.Bytes32ToAddressMappingSlot storage withdrawers = WITHDRAWERS_SLOT.getStorageBytes32ToAddressMapping();
        uint256 validatorCount = VALIDATORS_COUNT_SLOT.getUint256();

        publicKey = publicKeysStore.value[_idx];
        signature = signaturesStore.value[_idx];
        withdrawer = withdrawers.value[sha256(BytesLib.pad64(publicKey))];
        funded = _idx < validatorCount;
    }

    function setWithdrawer(bytes memory _publicKey, address _newWithdrawer) external {
        bytes32 pubkeyRoot = sha256(BytesLib.pad64(_publicKey));
        StateLib.Bytes32ToAddressMappingSlot storage publicKeyOwnership = WITHDRAWERS_SLOT
            .getStorageBytes32ToAddressMapping();

        if (msg.sender != publicKeyOwnership.value[pubkeyRoot]) {
            revert Unauthorized();
        }

        publicKeyOwnership.value[pubkeyRoot] = _newWithdrawer;
    }

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

    function _deposit(address _withdrawer) internal {
        if (msg.value == 0 || msg.value % DEPOSIT_SIZE != 0) {
            revert InvalidMessageValue();
        }

        uint256 depositCount = msg.value / DEPOSIT_SIZE;
        uint256 validatorCount = VALIDATORS_COUNT_SLOT.getUint256();
        StateLib.BytesArraySlot storage publicKeysStore = PUBLIC_KEYS_SLOT.getStorageBytesArray();
        StateLib.BytesArraySlot storage signaturesStore = SIGNATURES_SLOT.getStorageBytesArray();
        bytes32 withdrawalCredentials = WITHDRAWAL_CREDENTIALS_SLOT.getBytes32();

        if (validatorCount + depositCount > publicKeysStore.value.length) {
            revert NotEnoughKeys();
        }

        StateLib.Bytes32ToAddressMappingSlot storage publicKeyOwnership = WITHDRAWERS_SLOT
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
}
