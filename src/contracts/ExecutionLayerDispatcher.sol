//SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.10;

import "./libs/FeeRecipientStorageLib.sol";
import "./interfaces/IStakingContractFeeDetails.sol";
import "./interfaces/IDispatcher.sol";

/// @title Execution Layer Fee Recipient
/// @author Kiln
/// @notice This contract can be used to receive fees from a validator and split them with a node operator
contract ExecutionLayerDispatcher is IDispatcher {
    using FeeRecipientStorageLib for bytes32;

    event Withdrawal(address indexed withdrawer, address indexed feeRecipient, uint256 rewards, uint256 fee);

    error FeeRecipientReceiveError(bytes errorData);
    error WithdrawerReceiveError(bytes errorData);
    error ZeroBalanceWithdrawal();
    error AlreadyInitialized();
    error InvalidCall();

    bytes32 internal constant STAKING_CONTRACT_ADDRESS_SLOT =
        keccak256("ExecutionLayerFeeRecipient.stakingContractAddress");
    uint256 internal constant BASIS_POINTS = 10_000;
    bytes32 internal constant VERSION_SLOT = keccak256("ExecutionLayerFeeRecipient.version");

    /// @notice Ensures an initialisation call has been called only once per _version value
    /// @param _version The current initialisation value
    modifier init(uint256 _version) {
        if (_version != VERSION_SLOT.getUint256() + 1) {
            revert AlreadyInitialized();
        }

        VERSION_SLOT.setUint256(_version);

        _;
    }

    /// @notice Constructor method allowing us to prevent calls to initCLFR by setting the appropriate version
    constructor(uint256 _version) {
        VERSION_SLOT.setUint256(_version);
    }

    /// @notice Initialize the contract by storing the staking contract and the public key in storage
    /// @param _stakingContract Address of the Staking Contract
    function initELD(address _stakingContract) external init(1) {
        STAKING_CONTRACT_ADDRESS_SLOT.setAddress(_stakingContract);
    }

    /// @notice Performs a withdrawal on this contract's balance
    function dispatch(bytes32 _publicKeyRoot) external payable {
        uint256 balance = address(this).balance;
        if (balance == 0) {
            revert ZeroBalanceWithdrawal();
        }
        IStakingContractFeeDetails stakingContract = IStakingContractFeeDetails(
            STAKING_CONTRACT_ADDRESS_SLOT.getAddress()
        );
        address withdrawer = stakingContract.getWithdrawerFromPublicKeyRoot(_publicKeyRoot);
        uint256 feeBps = stakingContract.getELFee();
        address feeRecipient = stakingContract.getOperatorFeeRecipient(_publicKeyRoot);
        uint256 fee = (balance * feeBps) / BASIS_POINTS;
        (bool status, bytes memory data) = withdrawer.call{value: balance - fee}("");
        if (status == false) {
            revert WithdrawerReceiveError(data);
        }
        if (fee > 0) {
            (status, data) = feeRecipient.call{value: fee}("");
            if (status == false) {
                revert FeeRecipientReceiveError(data);
            }
        }
        emit Withdrawal(withdrawer, feeRecipient, balance - fee, fee);
    }

    /// @notice Retrieve the staking contract address
    function getStakingContract() external view returns (address) {
        return STAKING_CONTRACT_ADDRESS_SLOT.getAddress();
    }

    /// @notice Retrieve the assigned withdrawer for the given public key root
    /// @param _publicKeyRoot Public key root to get the owner
    function getWithdrawer(bytes32 _publicKeyRoot) external view returns (address) {
        IStakingContractFeeDetails stakingContract = IStakingContractFeeDetails(
            STAKING_CONTRACT_ADDRESS_SLOT.getAddress()
        );
        return stakingContract.getWithdrawerFromPublicKeyRoot(_publicKeyRoot);
    }

    receive() external payable {
        revert InvalidCall();
    }

    fallback() external payable {
        revert InvalidCall();
    }
}
