//SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.10;

/// @title Minimal Permissioned Treasury
/// @author Kiln
/// @notice You can use this contract to store funds and split them on a permissioned call
contract Treasury {
    error InvalidCall();
    error InvalidArrayLengths();
    error InvalidEmptyArray();
    error Unauthorized();
    error TransferError(bytes err);
    error InvalidAmount();
    error Locked();
    error InvalidPercents();

    uint256 constant BASIS_POINT = 10_000;

    address public admin;
    address[] public recipients;
    uint256[] public percents;
    uint256 internal locked = 1;

    constructor(
        address _admin,
        address[] memory _recipients,
        uint256[] memory _percents
    ) {
        if (_recipients.length != _percents.length) {
            revert InvalidArrayLengths();
        }

        if (_recipients.length == 0) {
            revert InvalidEmptyArray();
        }

        _checkPercents(_percents);

        admin = _admin;
        recipients = _recipients;
        percents = _percents;
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) {
            revert Unauthorized();
        }
        _;
    }

    modifier lock() {
        if (locked == 2) {
            revert Locked();
        }
        locked = 2;
        _;
        locked = 1;
    }

    /// @notice Sets the splitting parameters for the withdrawal
    /// @param _recipients The list of recipients to withdraw the funds to
    /// @param _percents The list of percents to use for the splitting
    function setParameters(address[] memory _recipients, uint256[] memory _percents) external onlyAdmin {
        if (_recipients.length != _percents.length) {
            revert InvalidArrayLengths();
        }

        if (_recipients.length == 0) {
            revert InvalidEmptyArray();
        }

        _checkPercents(_percents);

        recipients = _recipients;
        percents = _percents;
    }

    /// @notice Withdraws the current balance based on the provided percents, expected in basis point.
    /// @notice If the sum is greater than 10_000, transfers will end up failing
    /// @param _amount Amount to split between recipients
    function withdraw(uint256 _amount) external onlyAdmin lock {
        if (_amount > address(this).balance) {
            revert InvalidAmount();
        }

        for (uint256 idx = 0; idx < recipients.length; ++idx) {
            uint256 amountToTransfer = (_amount * percents[idx]) / BASIS_POINT;
            (bool status, bytes memory data) = recipients[idx].call{value: amountToTransfer}("");
            if (!status) {
                revert TransferError(data);
            }
        }
    }

    /// @notice Empty receiver
    receive() external payable {}

    /// @notice Fallback prevention
    fallback() external payable {
        revert InvalidCall();
    }

    /// @notice Checks that the sum of percents is equal to 10_000 (100 %)
    /// @param _percents List of percents
    function _checkPercents(uint256[] memory _percents) internal pure {
        uint256 sum;
        for (uint256 idx = 0; idx < _percents.length; ) {
            sum += _percents[idx];
            unchecked {
                ++idx;
            }
        }
        if (sum != BASIS_POINT) {
            revert InvalidPercents();
        }
    }
}
