//SPDX-License-Identifier: MIT
pragma solidity >=0.8.10;

library State {
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

    bytes32 internal constant VERSION_SLOT = keccak256("State.version");

    function getVersion() internal view returns (uint256) {
        return getUint256(VERSION_SLOT);
    }

    function setVersion(uint256 _newVersion) internal {
        setUint256(VERSION_SLOT, _newVersion);
    }

    bytes32 internal constant ADMIN_SLOT = keccak256("State.admin");

    function getAdmin() internal view returns (address) {
        return getAddress(ADMIN_SLOT);
    }

    function setAdmin(address _newAdmin) internal {
        setAddress(ADMIN_SLOT, _newAdmin);
    }

    bytes32 internal constant DEPOSIT_CONTRACT_SLOT = keccak256("State.depositContract");

    function getDepositContract() internal view returns (address) {
        return getAddress(DEPOSIT_CONTRACT_SLOT);
    }

    function setDepositContract(address _newAdmin) internal {
        setAddress(DEPOSIT_CONTRACT_SLOT, _newAdmin);
    }

    bytes32 internal constant WITHDRAWAL_CREDENTIALS_SLOT = keccak256("State.withdrawalCredentials");

    function getWithdrawalCredentials() internal view returns (bytes32) {
        return getBytes32(WITHDRAWAL_CREDENTIALS_SLOT);
    }

    function setWithdrawalCredentials(bytes32 _newCredentials) internal {
        setBytes32(WITHDRAWAL_CREDENTIALS_SLOT, _newCredentials);
    }

    bytes32 internal constant OPERATORS_SLOT = keccak256("State.operators");

    struct OperatorInfo {
        address operator;
        uint256 limit;
        bytes[] publicKeys;
        bytes[] signatures;
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

    bytes32 internal constant OPERATOR_SELECTION_INFO_SLOT = keccak256("State.operatorSelectionInfo");

    struct OperatorSelectionInfo {
        uint32 availableKeys;
        uint32 funded;
    }

    struct UintToUintMappingSlot {
        mapping(uint256 => uint256) value;
    }

    function getOperatorInfo(uint256 _index) internal view returns (OperatorSelectionInfo memory osi) {
        UintToUintMappingSlot storage p;
        bytes32 slot = OPERATOR_SELECTION_INFO_SLOT;

        assembly {
            p.slot := slot
        }

        uint256 slotIndex = _index / 4;
        uint256 innerIndex = _index % 4;

        uint256 slotValue = p.value[slotIndex];

        osi.availableKeys = uint32(slotValue >> ((innerIndex * 8) * 8));
        osi.funded = uint32(slotValue >> (((innerIndex * 8) + 4) * 8));
    }

    function setOperatorInfo(
        uint256 _index,
        uint32 _availableKeys,
        uint32 _funded
    ) internal {
        UintToUintMappingSlot storage p;
        bytes32 slot = OPERATOR_SELECTION_INFO_SLOT;

        assembly {
            p.slot := slot
        }

        uint256 slotIndex = _index / 4;
        uint256 innerIndex = _index % 4;

        p.value[slotIndex] &= (type(uint256).max - (0xFFFFFFFFFFFFFFFF << ((innerIndex * 8) * 8)));
        p.value[slotIndex] +=
            (uint256(_availableKeys) << ((innerIndex * 8) * 8)) +
            (uint256(_funded) << (((innerIndex * 8) + 4) * 8));
    }

    bytes32 internal constant TOTAL_AVAILABLE_VALIDATORS_SLOT = keccak256("State.totalAvailableValidators");

    function getTotalAvailableValidators() internal view returns (uint256) {
        return getUint256(TOTAL_AVAILABLE_VALIDATORS_SLOT);
    }

    function setTotalAvailableValidators(uint256 _newTotal) internal {
        setUint256(TOTAL_AVAILABLE_VALIDATORS_SLOT, _newTotal);
    }

    bytes32 internal constant WITHDRAWERS_SLOT = keccak256("State.withdrawers");

    struct WithdrawersSlot {
        mapping(bytes32 => address) value;
    }

    function getWithdrawers() internal pure returns (WithdrawersSlot storage p) {
        bytes32 slot = OPERATORS_SLOT;
        assembly {
            p.slot := slot
        }
    }
}
