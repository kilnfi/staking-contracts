//SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.10;

import "./libs/FeeRecipientStorageLib.sol";
import "./interfaces/IStakingContractFeeDetails.sol";

/// @title Consensus Layer Fee Recipient
/// @author Kiln
/// @notice This contract can be used to receive fees from a validator and split them with a node operator
contract ConsensusLayerFeeRecipient {
    using FeeRecipientStorageLib for bytes32;

    event Withdrawal(address indexed withdrawer, address indexed feeRecipient, uint256 rewards, uint256 fee);

    error FeeRecipientReceiveError(bytes errorData);
    error WithdrawerReceiveError(bytes errorData);
    error ZeroBalanceWithdrawal();
    error AlreadyInitialized();
    error InvalidCall();

    bytes32 internal constant STAKING_CONTRACT_ADDRESS_SLOT =
        keccak256("ConsensusLayerFeeRecipient.stakingContractAddress");
    bytes32 internal constant VALIDATOR_PUBLIC_KEY_SLOT = keccak256("ConsensusLayerFeeRecipient.validatorPublicKey");
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

    /// @notice Initialize the contract by storing the staking contract and the public key in storage
    /// @param _stakingContract Address of the Staking Contract
    /// @param _publicKeyRoot Hash of the public key linked to this fee recipient
    function initCLFR(address _stakingContract, bytes32 _publicKeyRoot) external init(1) {
        STAKING_CONTRACT_ADDRESS_SLOT.setAddress(_stakingContract);
        VALIDATOR_PUBLIC_KEY_SLOT.setBytes32(_publicKeyRoot);
    }

    /// @notice Performs a withdrawal on this contract's balance
    function withdraw() external {
        uint256 balance = address(this).balance;
        if (balance == 0) {
            revert ZeroBalanceWithdrawal();
        }
        IStakingContractFeeDetails stakingContract = IStakingContractFeeDetails(
            STAKING_CONTRACT_ADDRESS_SLOT.getAddress()
        );
        bytes32 pubKeyRoot = VALIDATOR_PUBLIC_KEY_SLOT.getBytes32();
        address withdrawer = stakingContract.getWithdrawerFromPublicKeyRoot(pubKeyRoot);
        uint256 feeBps = stakingContract.getCLFee();
        address feeRecipient = stakingContract.getOperatorFeeRecipient(pubKeyRoot);

        uint256 fee;
        if (balance >= 32 ether) {
            // withdrawing a healthy & exited validator
            fee = ((balance - 32 ether) * feeBps) / BASIS_POINTS;
        } else if (balance <= 16 ether) {
            // withdrawing from what looks like skimming
            fee = (balance * feeBps) / BASIS_POINTS;
        } else {
            // withdrawing from slashed validator (< 32 eth and > 16 eth)
            fee = 0;
        }

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

    /// @notice Retrieve the assigned withdrawer
    function getWithdrawer() external view returns (address) {
        IStakingContractFeeDetails stakingContract = IStakingContractFeeDetails(
            STAKING_CONTRACT_ADDRESS_SLOT.getAddress()
        );
        bytes32 pubKeyRoot = VALIDATOR_PUBLIC_KEY_SLOT.getBytes32();
        address withdrawer = stakingContract.getWithdrawerFromPublicKeyRoot(pubKeyRoot);
        return withdrawer;
    }

    /// @notice Retrieve the assigned public key root
    function getPublicKeyRoot() external view returns (bytes32) {
        return VALIDATOR_PUBLIC_KEY_SLOT.getBytes32();
    }

    receive() external payable {}

    fallback() external payable {
        revert InvalidCall();
    }
}
