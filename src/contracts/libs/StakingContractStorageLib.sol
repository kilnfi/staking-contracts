//SPDX-License-Identifier: MIT
pragma solidity >=0.8.10;

library StakingContractStorageLib {
    function getUint256(bytes32 position) internal view returns (uint256 data) {
        assembly {
            data := sload(position)
        }
    }

    function setUint256(bytes32 position, uint256 data) internal {
        assembly {
            sstore(position, data)
        }
    }

    function getAddress(bytes32 position) internal view returns (address data) {
        assembly {
            data := sload(position)
        }
    }

    function setAddress(bytes32 position, address data) internal {
        assembly {
            sstore(position, data)
        }
    }

    function getBytes32(bytes32 position) internal view returns (bytes32 data) {
        assembly {
            data := sload(position)
        }
    }

    function setBytes32(bytes32 position, bytes32 data) internal {
        assembly {
            sstore(position, data)
        }
    }

    /* ========================================
    ===========================================
    =========================================*/

    bytes32 internal constant VERSION_SLOT = keccak256("StakingContract.version");

    function getVersion() internal view returns (uint256) {
        return getUint256(VERSION_SLOT);
    }

    function setVersion(uint256 _newVersion) internal {
        setUint256(VERSION_SLOT, _newVersion);
    }

    /* ========================================
    ===========================================
    =========================================*/

    bytes32 internal constant ADMIN_SLOT = keccak256("StakingContract.admin");

    function getAdmin() internal view returns (address) {
        return getAddress(ADMIN_SLOT);
    }

    function setAdmin(address _newAdmin) internal {
        setAddress(ADMIN_SLOT, _newAdmin);
    }

    /* ========================================
    ===========================================
    =========================================*/

    bytes32 internal constant DEPOSIT_CONTRACT_SLOT = keccak256("StakingContract.depositContract");

    function getDepositContract() internal view returns (address) {
        return getAddress(DEPOSIT_CONTRACT_SLOT);
    }

    function setDepositContract(address _newDepositContract) internal {
        setAddress(DEPOSIT_CONTRACT_SLOT, _newDepositContract);
    }

    /* ========================================
    ===========================================
    =========================================*/

    bytes32 internal constant OPERATORS_SLOT = keccak256("StakingContract.operators");

    struct OperatorInfo {
        address operator;
        address feeRecipient;
        uint256 limit;
        bytes[] publicKeys;
        bytes[] signatures;
        bool deactivated;
    }

    struct OperatorsSlot {
        OperatorInfo[] value;
    }

    function getOperators() internal pure returns (OperatorsSlot storage p) {
        bytes32 slot = OPERATORS_SLOT;
        assembly {
            p.slot := slot
        }
    }

    /* ========================================
    ===========================================
    =========================================*/

    bytes32 internal constant VALIDATORS_FUNDING_INFO_SLOT = keccak256("StakingContract.validatorsFundingInfo");

    struct ValidatorsFundingInfo {
        uint32 availableKeys;
        uint32 funded;
    }

    struct UintToUintMappingSlot {
        mapping(uint256 => uint256) value;
    }

    function getValidatorsFundingInfo(uint256 _index) internal view returns (ValidatorsFundingInfo memory vfi) {
        UintToUintMappingSlot storage p;
        bytes32 slot = VALIDATORS_FUNDING_INFO_SLOT;

        assembly {
            p.slot := slot
        }

        uint256 slotIndex = _index >> 2;
        uint256 innerIndex = (_index & 3) << 6;
        uint256 value = p.value[slotIndex] >> innerIndex;
        vfi.availableKeys = uint32(value);
        vfi.funded = uint32(value >> 32);
    }

    function setValidatorsFundingInfo(
        uint256 _index,
        uint32 _availableKeys,
        uint32 _funded
    ) internal {
        UintToUintMappingSlot storage p;
        bytes32 slot = VALIDATORS_FUNDING_INFO_SLOT;

        assembly {
            p.slot := slot
        }

        uint256 slotIndex = _index >> 2;
        uint256 innerIndex = (_index & 3) << 6;
        p.value[slotIndex] =
            (p.value[slotIndex] & (~(uint256(0xFFFFFFFFFFFFFFFF) << innerIndex))) |
            ((uint256(_availableKeys) | (uint256(_funded) << 32)) << innerIndex);
    }

    /* ========================================
    ===========================================
    =========================================*/

    bytes32 internal constant TOTAL_AVAILABLE_VALIDATORS_SLOT = keccak256("StakingContract.totalAvailableValidators");

    function getTotalAvailableValidators() internal view returns (uint256) {
        return getUint256(TOTAL_AVAILABLE_VALIDATORS_SLOT);
    }

    function setTotalAvailableValidators(uint256 _newTotal) internal {
        setUint256(TOTAL_AVAILABLE_VALIDATORS_SLOT, _newTotal);
    }

    /* ========================================
    ===========================================
    =========================================*/

    bytes32 internal constant WITHDRAWERS_SLOT = keccak256("StakingContract.withdrawers");

    struct WithdrawersSlot {
        mapping(bytes32 => address) value;
    }

    function getWithdrawers() internal pure returns (WithdrawersSlot storage p) {
        bytes32 slot = WITHDRAWERS_SLOT;
        assembly {
            p.slot := slot
        }
    }

    /* ========================================
    ===========================================
    =========================================*/

    struct OperatorIndex {
        bool enabled;
        uint32 operatorIndex;
    }

    struct OperatorIndexPerValidatorSlot {
        mapping(bytes32 => OperatorIndex) value;
    }

    bytes32 internal constant OPERATOR_INDEX_PER_VALIDATOR_SLOT =
        keccak256("StakingContract.operatorIndexPerValidator");

    function getOperatorIndexPerValidator() internal pure returns (OperatorIndexPerValidatorSlot storage p) {
        bytes32 slot = OPERATOR_INDEX_PER_VALIDATOR_SLOT;
        assembly {
            p.slot := slot
        }
    }

    /* ========================================
    ===========================================
    =========================================*/

    bytes32 internal constant EL_FEE_SLOT = keccak256("StakingContract.executionLayerFee");

    function getELFee() internal view returns (uint256) {
        return getUint256(EL_FEE_SLOT);
    }

    function setELFee(uint256 _newElFee) internal {
        setUint256(EL_FEE_SLOT, _newElFee);
    }

    /* ========================================
    ===========================================
    =========================================*/

    bytes32 internal constant CL_FEE_SLOT = keccak256("StakingContract.consensusLayerFee");

    function getCLFee() internal view returns (uint256) {
        return getUint256(CL_FEE_SLOT);
    }

    function setCLFee(uint256 _newClFee) internal {
        setUint256(CL_FEE_SLOT, _newClFee);
    }

    /* ========================================
    ===========================================
    =========================================*/

    bytes32 internal constant EL_DISPATCHER_SLOT = keccak256("StakingContract.executionLayerDispatcher");

    function getELDispatcher() internal view returns (address) {
        return getAddress(EL_DISPATCHER_SLOT);
    }

    function setELDispatcher(address _newElDispatcher) internal {
        setAddress(EL_DISPATCHER_SLOT, _newElDispatcher);
    }

    /* ========================================
    ===========================================
    =========================================*/

    bytes32 internal constant CL_DISPATCHER_SLOT = keccak256("StakingContract.consensusLayerDispatcher");

    function getCLDispatcher() internal view returns (address) {
        return getAddress(CL_DISPATCHER_SLOT);
    }

    function setCLDispatcher(address _newClDispatcher) internal {
        setAddress(CL_DISPATCHER_SLOT, _newClDispatcher);
    }

    /* ========================================
    ===========================================
    =========================================*/

    bytes32 internal constant FEE_RECIPIENT_IMPLEMENTATION_SLOT =
        keccak256("StakingContract.feeRecipientImplementation");

    function getFeeRecipientImplementation() internal view returns (address) {
        return getAddress(FEE_RECIPIENT_IMPLEMENTATION_SLOT);
    }

    function setFeeRecipientImplementation(address _newFeeRecipientImplementation) internal {
        setAddress(FEE_RECIPIENT_IMPLEMENTATION_SLOT, _newFeeRecipientImplementation);
    }
}
