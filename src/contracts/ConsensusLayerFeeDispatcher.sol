//SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.10;

import "./libs/DispatchersStorageLib.sol";
import "./interfaces/IStakingContractFeeDetails.sol";
import "./interfaces/IFeeDispatcher.sol";

/// @title Consensus Layer Fee Recipient
/// @author Kiln
/// @notice This contract can be used to receive fees from a validator and split them with a node operator
contract ConsensusLayerFeeDispatcher is IFeeDispatcher {
    using DispatchersStorageLib for bytes32;

    event Withdrawal(
        address indexed withdrawer,
        address indexed feeRecipient,
        bytes32 pubKeyRoot,
        uint256 rewards,
        uint256 nodeOperatorFee,
        uint256 treasuryFee
    );

    error TreasuryReceiveError(bytes errorData);
    error FeeRecipientReceiveError(bytes errorData);
    error WithdrawerReceiveError(bytes errorData);
    error ZeroBalanceWithdrawal();
    error AlreadyInitialized();
    error InvalidCall();

    bytes32 internal constant STAKING_CONTRACT_ADDRESS_SLOT =
        keccak256("ConsensusLayerFeeRecipient.stakingContractAddress");
    uint256 internal constant BASIS_POINTS = 10_000;
    bytes32 internal constant VERSION_SLOT = keccak256("ConsensusLayerFeeRecipient.version");

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

    /// @notice Initialize the contract by storing the staking contract
    /// @param _stakingContract Address of the Staking Contract
    function initCLD(address _stakingContract) external init(1) {
        STAKING_CONTRACT_ADDRESS_SLOT.setAddress(_stakingContract);
    }

    /// @notice Performs a withdrawal on this contract's balance
    function dispatch(bytes32 _publicKeyRoot) external payable {
        IStakingContractFeeDetails stakingContract = IStakingContractFeeDetails(
            STAKING_CONTRACT_ADDRESS_SLOT.getAddress()
        );

        uint256 balance = address(this).balance; // this has taken into account msg.value
        if (balance == 0) {
            revert ZeroBalanceWithdrawal();
        }

        bool exitRequested = stakingContract.getExitRequestedFromRoot(_publicKeyRoot);
        bool withdrawn = stakingContract.getWithdrawnFromPublicKeyRoot(_publicKeyRoot);

        uint256 nonExemptBalance = balance;

        if (exitRequested && balance >= 31 ether && !withdrawn) {
            // If the skimmed rewards were withdrawn and the validator then underperformed an healthy exit can be slightly lower than 32 ETH
            // We exempt the balance up to 32 ETH, happens only once.
            // !withdrawn prevents this logic being reused to not pay the fee on rewards
            uint256 exemption = nonExemptBalance > 32 ether ? 32 ether : nonExemptBalance;
            nonExemptBalance -= exemption;
            stakingContract.toggleWithdrawnFromPublicKeyRoot(_publicKeyRoot);
        }
        // In case of slashing the exit is not requested we don't exempt anything
        // This is in case of slashing, the staker will be rebated manually
        // A slashed validator may have accumulated enough skimmed rewards to still have a balance > 32 ETH
        // All of this will be taken into account and the staker will be compensated for the commission taken on its principal
        // and the loss according to the SLA described in the Terms&Conditions

        uint256 globalFee = (nonExemptBalance * stakingContract.getGlobalFee()) / BASIS_POINTS;
        uint256 operatorFee = (globalFee * stakingContract.getOperatorFee()) / BASIS_POINTS;
        address operator = stakingContract.getOperatorFeeRecipient(_publicKeyRoot);
        address treasury = stakingContract.getTreasury();
        address withdrawer = stakingContract.getWithdrawerFromPublicKeyRoot(_publicKeyRoot);

        (bool status, bytes memory data) = withdrawer.call{value: balance - globalFee}("");
        if (status == false) {
            revert WithdrawerReceiveError(data);
        }
        if (globalFee > 0) {
            (status, data) = treasury.call{value: globalFee - operatorFee}("");
            if (status == false) {
                revert TreasuryReceiveError(data);
            }
        }
        if (operatorFee > 0) {
            (status, data) = operator.call{value: operatorFee}("");
            if (status == false) {
                revert FeeRecipientReceiveError(data);
            }
        }
        emit Withdrawal(
            withdrawer,
            operator,
            _publicKeyRoot,
            balance - globalFee,
            operatorFee,
            globalFee - operatorFee
        );
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
