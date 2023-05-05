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

    function getBool(bytes32 position) internal view returns (bool data) {
        assembly {
            data := sload(position)
        }
    }

    function setBool(bytes32 position, bool data) internal {
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
    bytes32 internal constant PENDING_ADMIN_SLOT = keccak256("StakingContract.pendingAdmin");

    function getAdmin() internal view returns (address) {
        return getAddress(ADMIN_SLOT);
    }

    function setAdmin(address _newAdmin) internal {
        setAddress(ADMIN_SLOT, _newAdmin);
    }

    function getPendingAdmin() internal view returns (address) {
        return getAddress(PENDING_ADMIN_SLOT);
    }

    function setPendingAdmin(address _newPendingAdmin) internal {
        setAddress(PENDING_ADMIN_SLOT, _newPendingAdmin);
    }

    /* ========================================
    ===========================================
    =========================================*/

    bytes32 internal constant TREASURY_SLOT = keccak256("StakingContract.treasury");

    function getTreasury() internal view returns (address) {
        return getAddress(TREASURY_SLOT);
    }

    function setTreasury(address _newTreasury) internal {
        setAddress(TREASURY_SLOT, _newTreasury);
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

    /// Validator funding information is stored in a packed fashion
    /// We fit 4 vfi per storage slot.
    /// Each vfi is stored in 64 bits, with the following layout:
    /// 32 bits for the number of available keys
    /// 32 bits for the number of funded keys

    uint256 internal constant FUNDED_OFFSET = 32;

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

        uint256 slotIndex = _index >> 2; // divide by 4
        uint256 innerIndex = (_index & 3) << 6; // modulo 4, multiply by 64
        uint256 value = p.value[slotIndex] >> innerIndex;
        vfi.availableKeys = uint32(value);
        vfi.funded = uint32(value >> FUNDED_OFFSET);
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

        uint256 slotIndex = _index >> 2; // divide by 4
        uint256 innerIndex = (_index & 3) << 6; // modulo 4, multiply by 64
        p.value[slotIndex] =
            (p.value[slotIndex] & (~(uint256(0xFFFFFFFFFFFFFFFF) << innerIndex))) | // clear the bits we want to set
            ((uint256(_availableKeys) | (uint256(_funded) << FUNDED_OFFSET)) << innerIndex);
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

    bytes32 internal constant GLOBAL_FEE_SLOT = keccak256("StakingContract.globalFee");

    function getGlobalFee() internal view returns (uint256) {
        return getUint256(GLOBAL_FEE_SLOT);
    }

    function setGlobalFee(uint256 _newTreasuryFee) internal {
        setUint256(GLOBAL_FEE_SLOT, _newTreasuryFee);
    }

    /* ========================================
    ===========================================
    =========================================*/

    bytes32 internal constant OPERATOR_FEE_SLOT = keccak256("StakingContract.operatorFee");

    function getOperatorFee() internal view returns (uint256) {
        return getUint256(OPERATOR_FEE_SLOT);
    }

    function setOperatorFee(uint256 _newOperatorFee) internal {
        setUint256(OPERATOR_FEE_SLOT, _newOperatorFee);
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

    /* ========================================
    ===========================================
    =========================================*/

    bytes32 internal constant WITHDRAWER_CUSTOMIZATION_ENABLED_SLOT =
        keccak256("StakingContract.withdrawerCustomizationEnabled");

    function getWithdrawerCustomizationEnabled() internal view returns (bool) {
        return getBool(WITHDRAWER_CUSTOMIZATION_ENABLED_SLOT);
    }

    function setWithdrawerCustomizationEnabled(bool _enabled) internal {
        setBool(WITHDRAWER_CUSTOMIZATION_ENABLED_SLOT, _enabled);
    }

    /* ========================================
    ===========================================
    =========================================*/

    bytes32 internal constant EXIT_REQUEST_MAPPING_SLOT =
        bytes32(uint256(keccak256("StakingContract.exitRequest")) - 1);

    struct ExitRequestMap {
        mapping(bytes32 => bool) value;
    }

    function getExitRequestMap() internal pure returns (ExitRequestMap storage p) {
        bytes32 slot = EXIT_REQUEST_MAPPING_SLOT;
        assembly {
            p.slot := slot
        }
    }

    /* ========================================
    ===========================================
    =========================================*/

    bytes32 internal constant WITHDRAWN_MAPPING_SLOT = bytes32(uint256(keccak256("StakingContract.withdrawn")) - 1);

    struct WithdrawnMap {
        mapping(bytes32 => bool) value;
    }

    function getWithdrawnMap() internal pure returns (WithdrawnMap storage p) {
        bytes32 slot = WITHDRAWN_MAPPING_SLOT;
        assembly {
            p.slot := slot
        }
    }

    /* ========================================
    ===========================================
    =========================================*/

    bytes32 internal constant GLOBAL_COMMISSION_LIMIT_SLOT =
        bytes32(uint256(keccak256("StakingContract.globalCommissionLimit")) - 1);

    function getGlobalCommissionLimit() internal view returns (uint256) {
        return getUint256(GLOBAL_COMMISSION_LIMIT_SLOT);
    }

    function setGlobalCommissionLimit(uint256 value) internal {
        setUint256(GLOBAL_COMMISSION_LIMIT_SLOT, value);
    }

    /* ========================================
    ===========================================
    =========================================*/

    bytes32 internal constant OPERATOR_COMMISSION_LIMIT_SLOT =
        bytes32(uint256(keccak256("StakingContract.operatorCommissionLimit")) - 1);

    function getOperatorCommissionLimit() internal view returns (uint256) {
        return getUint256(OPERATOR_COMMISSION_LIMIT_SLOT);
    }

    function setOperatorCommissionLimit(uint256 value) internal {
        setUint256(OPERATOR_COMMISSION_LIMIT_SLOT, value);
    }

    /* ========================================
    ===========================================
    =========================================*/

    bytes32 internal constant DEPOSIT_STOPPED_SLOT = bytes32(uint256(keccak256("StakingContract.depositStopped")) - 1);

    function getDepositStopped() internal view returns (bool) {
        return getBool(DEPOSIT_STOPPED_SLOT);
    }

    function setDepositStopped(bool val) internal {
        setBool(DEPOSIT_STOPPED_SLOT, val);
    }

    /* ========================================
    ===========================================
    =========================================*/

    bytes32 internal constant LAST_VALIDATOR_EDIT_SLOT =
        bytes32(uint256(keccak256("StakingContract.lastValidatorsEdit")) - 1);

    function getLastValidatorEdit() internal view returns (uint256) {
        return getUint256(LAST_VALIDATOR_EDIT_SLOT);
    }

    function setLastValidatorEdit(uint256 value) internal {
        setUint256(LAST_VALIDATOR_EDIT_SLOT, value);
    }
}
