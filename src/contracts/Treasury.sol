//SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.10;

/// @title Minimal Permissioned Treasury
/// @author Kiln
/// @notice You can use this contract to store funds and split them on a permissioned call
contract Treasury {
    error InvalidCall();
    error InvalidArrayLengths();
    error InvalidEmptyArray();
    error InvalidPercentAmount();
    error Unauthorized();
    error TransferError(bytes err);

    uint256 constant BASIS_POINT = 10_000;

    address public admin;

    constructor(address _admin) {
        admin = _admin;
    }

    /// @notice Withdraws the current balance based on the provided percents, expected in basis point.
    /// @notice If the sum is greater than 10_000, transfers will end up failing
    /// @param _recipients Array of recipients that receive the funds.
    /// @param _balancePercents Array of percent of the balance allocated to each recipient at the same index.
    function withdraw(address[] calldata _recipients, uint256[] calldata _balancePercents) external {
        if (msg.sender != admin) {
            revert Unauthorized();
        }

        if (_recipients.length != _balancePercents.length) {
            revert InvalidArrayLengths();
        }

        if (_recipients.length == 0) {
            revert InvalidEmptyArray();
        }

        uint256 balance = address(this).balance;

        for (uint256 idx = 0; idx < _recipients.length; ++idx) {
            if (_balancePercents[idx] > BASIS_POINT) {
                revert InvalidPercentAmount();
            }
            uint256 amount = (balance * _balancePercents[idx]) / BASIS_POINT;
            (bool status, bytes memory data) = _recipients[idx].call{value: amount}("");
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
}
