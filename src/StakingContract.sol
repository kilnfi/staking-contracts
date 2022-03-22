// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.10;

import "./libs/StateLib.sol";
import "./libs/UintLib.sol";
import "./libs/BytesLib.sol";

import "./interfaces/IDepositContract.sol";
import "./test/console.sol";

contract StakingContract {
    using StateLib for bytes32;

    // review(nmvalera): we can hard code all *_SLOT values
    bytes32 internal constant FEE_SLOT = keccak256("StakingContract.fee");
    bytes32 internal constant ADMIN_SLOT = keccak256("StakingContract.admin");

    // review(nmvalera): can we add an entry for the node operator like OPERATOR_SLOT
    bytes32 internal constant VERSION_SLOT = keccak256("StakingContract.version");
    bytes32 internal constant SIGNATURES_SLOT = keccak256("StakingContract.signatures");
    bytes32 internal constant PUBLIC_KEYS_SLOT = keccak256("StakingContract.publicKeys");

    // review(nmvalera): rename VALIDATOR_COUNT_SLOT -> VALIDATORS_COUNT_SLOT
    bytes32 internal constant VALIDATOR_COUNT_SLOT = keccak256("StakingContract.validatorCount");
    bytes32 internal constant DEPOSIT_CONTRACT_SLOT = keccak256("StakingContract.depositContract");

    // review(nmvalera): rename PUBLIC_KEY_OWNERSHIP_SLOT -> WITHDRAWERS_SLOT
    bytes32 internal constant PUBLIC_KEY_OWNERSHIP_SLOT = keccak256("StakingContract.publicKeyOwnership");
    bytes32 internal constant WITHDRAWAL_CREDENTIALS_SLOT = keccak256("StakingContract.withdrawalCredentials");
    
    // review(nmvalera): can we add an entry for the operator

    uint256 public constant DEPOSIT_SIZE = 32 ether;
    uint256 public constant PUBLIC_KEY_LENGTH = 48;
    uint256 public constant SIGNATURE_LENGTH = 96;

    error Unauthorized();
    error AlreadyInitialized();
    error InvalidCall();
    error InvalidArgument();
    error InvalidValue();
    error NotEnoughKeys();

    event Deposit(address indexed caller, address indexed withdrawer, bytes publicKey, bytes32 publicKeyRoot);

    modifier init(uint256 _version) {
        if (_version != VERSION_SLOT.getUint256() + 1) {
            revert AlreadyInitialized();
        }

        VERSION_SLOT.setUint256(_version);

        _;
    }

    modifier onlyAdmin() {
        if (msg.sender != ADMIN_SLOT.getAddress()) {
            revert Unauthorized();
        }

        _;
    }

    function initialize_1(
        address _admin,
        uint256 _fee,
        address _depositContract,
        bytes32 _withdrawalCredentials
    ) external init(1) {
        ADMIN_SLOT.setAddress(_admin);
        FEE_SLOT.setUint256(_fee);
        DEPOSIT_CONTRACT_SLOT.setAddress(_depositContract);
        WITHDRAWAL_CREDENTIALS_SLOT.setBytes32(_withdrawalCredentials);
    }

    // review(nmvalera): if I understand correctly this one should be named fundedValidatorsCount()
    function getValidatorCount() external view returns (uint256) {
        return VALIDATOR_COUNT_SLOT.getUint256();
    }

    // question(nmvalera): rename getKeyCount -> totalValidatorCount
    function getKeyCount() external view returns (uint256) {
        return PUBLIC_KEYS_SLOT.getStorageBytesArray().value.length;
    }

    function getWithdrawer(bytes memory _publicKey) external view returns (address) {
        bytes32 pubkeyRoot = sha256(BytesLib.pad64(_publicKey));
        StateLib.Bytes32ToAddressMappingSlot storage publicKeyOwnership = PUBLIC_KEY_OWNERSHIP_SLOT
            .getStorageBytes32ToAddressMapping();
        return publicKeyOwnership.value[pubkeyRoot];
    }

    function getFee() external view returns (uint256) {
        return FEE_SLOT.getUint256();
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

    // review(nmvalera): rename to registerValidators
    // review(nmvalera): modifier should be onlyOperator (modifier to be created)
    // review(nmvalera): why not doing the same as River function addValidators(uint256 _keyCount,bytes calldata _publicKeys, bytes calldata _signatures)? It will be easier for skillz to operate all contracts the same way 
    function registerValidatorKeys(bytes[] memory publicKeys, bytes[] memory signatures) external onlyAdmin {
        if (publicKeys.length != signatures.length || publicKeys.length == 0) {
            revert InvalidArgument();
        }


        StateLib.BytesArraySlot storage publicKeysStore = PUBLIC_KEYS_SLOT.getStorageBytesArray();
        StateLib.BytesArraySlot storage signaturesStore = SIGNATURES_SLOT.getStorageBytesArray();

        for (uint256 i; i < publicKeys.length; ) {
            if (publicKeys[i].length != 48 || signatures[i].length != 96) {
                // review(nmvalera): is it possible to be more explicit in the message, like "invalid pubkey at position {i} has length {publicKeys[i].length} expects 48"
                revert InvalidArgument();
            }
            publicKeysStore.value.push(publicKeys[i]);
            signaturesStore.value.push(signatures[i]);
            // question(nmvalera): what does unchecked mean?
            unchecked {
                ++i;
            }
        }
    }

    // review(nmvalera): add a method getValidator(uint256 _idx) that returns a validator (pubkey, signature, withdrawer, and funded)

    // review(nmvalera): add a method removeValidators(uint256[] calldata _indexes)

    function setWithdrawer(bytes memory _publicKey, address _newWithdrawer) external {
        bytes32 pubkeyRoot = sha256(BytesLib.pad64(_publicKey));
        StateLib.Bytes32ToAddressMappingSlot storage publicKeyOwnership = PUBLIC_KEY_OWNERSHIP_SLOT
            .getStorageBytes32ToAddressMapping();

        if (msg.sender != publicKeyOwnership.value[pubkeyRoot]) {
            // review(nmvalera): is it possible to be more explicit in the message, like "{msg.sender} is not the withdrawer for {_publicKey}"
            revert Unauthorized();
        }

        publicKeyOwnership.value[pubkeyRoot] = _newWithdrawer;
    }

    // review(nmvalera): following up on discussion with ledger we should not need the fee upfront
    function setFee(uint256 _newFee) external onlyAdmin {
        FEE_SLOT.setUint256(_newFee);
    }

    // review(nmvalera): rename _useKeys -> _depositValidator 
    function _useKeys(
        // review(nmvalera): rename _publicKey -> _pubkey (let's try to be consistent every where using pubkey and not publicKey)
        bytes memory _publicKey,
        bytes memory _signature,
        bytes32 _withdrawalCredentials,
        address _withdrawer
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

        require(address(this).balance == targetBalance, "EXPECTING_DEPOSIT_TO_HAPPEN");

        // review(nmvalera): seems that setting withdrawer and emitting Deposit event should be part of _deposit() function. 2 reasons: 
        // 1. we scope the responsibility of _useKeys() to only depositing a key to the official deposit contract
        // 2. we avoid to load storage publicKeyOwnership at every step of the loop
        StateLib.Bytes32ToAddressMappingSlot storage publicKeyOwnership = PUBLIC_KEY_OWNERSHIP_SLOT
            .getStorageBytes32ToAddressMapping();

        publicKeyOwnership.value[pubkeyRoot] = _withdrawer;

        emit Deposit(msg.sender, _withdrawer, _publicKey, pubkeyRoot);
    }

    function _deposit(address _withdrawer) internal {
        uint256 fee = FEE_SLOT.getUint256();

        if (msg.value == 0 || msg.value % (DEPOSIT_SIZE + fee) != 0) {
            // review(nmvalera): can we make the message more explicit like "expects value to be a multiple of {DEPOSIT_SIZE + fee} but got {msg.value}
            revert InvalidValue();
        }

        uint256 depositCount = msg.value / (DEPOSIT_SIZE + fee);
        uint256 validatorCount = VALIDATOR_COUNT_SLOT.getUint256();
        StateLib.BytesArraySlot storage publicKeysStore = PUBLIC_KEYS_SLOT.getStorageBytesArray();
        StateLib.BytesArraySlot storage signaturesStore = SIGNATURES_SLOT.getStorageBytesArray();
        bytes32 withdrawalCredentials = WITHDRAWAL_CREDENTIALS_SLOT.getBytes32();

        if (validatorCount + depositCount > publicKeysStore.value.length) {
            revert NotEnoughKeys();
        }

        for (uint256 i; i < depositCount; ) {
            _useKeys(
                publicKeysStore.value[validatorCount + i],
                signaturesStore.value[validatorCount + i],
                withdrawalCredentials,
                _withdrawer
            );
            unchecked {
                ++i;
            }
        }

        VALIDATOR_COUNT_SLOT.setUint256(validatorCount + depositCount);
    }
}
