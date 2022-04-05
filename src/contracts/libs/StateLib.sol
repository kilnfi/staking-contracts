//SPDX-License-Identifier: MIT
pragma solidity >=0.8.10;

library StateLib {
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

    struct Bytes32ToAddressMappingSlot {
        mapping(bytes32 => address) value;
    }

    function getStorageBytes32ToAddressMapping(bytes32 position)
        internal
        pure
        returns (Bytes32ToAddressMappingSlot storage r)
    {
        assembly {
            r.slot := position
        }
    }

    struct BytesArraySlot {
        bytes[] value;
    }

    function getStorageBytesArray(bytes32 position) internal pure returns (BytesArraySlot storage r) {
        assembly {
            r.slot := position
        }
    }
}
