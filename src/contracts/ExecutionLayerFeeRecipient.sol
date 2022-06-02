//SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.10;

import "./libs/ELFRStateLib.sol";

interface IStakingContractFeeDetails {
    function getWithdrawerFromPublicKeyRoot(bytes32 _publicKeyRoot) external view returns (address);

    function getELFeeBps() external view returns (uint256);

    function getELFeeTreasury() external view returns (address);
}

contract ExecutionLayerFeeRecipient {
    using ELFRStateLib for bytes32;
    error AlreadyInitialized();
    error WithdrawerTransferError(bytes errorData);
    error FeeRecipientTransferError(bytes errorData);
    error InvalidCall();

    uint256 internal constant BASIS_POINTS = 10_000;

    bytes32 internal constant VERSION_SLOT = keccak256("ExecutionLayerFeeRecipient.version");
    bytes32 internal constant STAKING_CONTRACT_ADDRESS_SLOT =
        keccak256("ExecutionLayerFeeRecipient.stakingContractAddress");
    bytes32 internal constant VALIDATOR_PUBLIC_KEY_SLOT = keccak256("ExecutionLayerFeeRecipient.validatorPublicKey");

    /// @notice Ensures an initialisation call has been called only once per _version value
    /// @param _version The current initialisation value
    modifier init(uint256 _version) {
        if (_version != VERSION_SLOT.getUint256() + 1) {
            revert AlreadyInitialized();
        }

        VERSION_SLOT.setUint256(_version);

        _;
    }

    function initELFR(address _stakingContract, bytes32 _publicKeyRoot) external init(1) {
        STAKING_CONTRACT_ADDRESS_SLOT.setAddress(_stakingContract);
        VALIDATOR_PUBLIC_KEY_SLOT.setBytes32(_publicKeyRoot);
    }

    function withdraw() external {
        IStakingContractFeeDetails stakingContract = IStakingContractFeeDetails(
            STAKING_CONTRACT_ADDRESS_SLOT.getAddress()
        );
        address withdrawer = stakingContract.getWithdrawerFromPublicKeyRoot(VALIDATOR_PUBLIC_KEY_SLOT.getBytes32());
        uint256 feeBps = stakingContract.getELFeeBps();
        address feeRecipient = stakingContract.getELFeeTreasury();
        uint256 balance = address(this).balance;
        uint256 fee = (balance * feeBps) / BASIS_POINTS;
        (bool status, bytes memory data) = withdrawer.call{value: balance - fee}("");
        if (status == false) {
            revert WithdrawerTransferError(data);
        }
        (status, data) = feeRecipient.call{value: fee}("");
        if (status == false) {
            revert FeeRecipientTransferError(data);
        }
    }

    receive() external payable {}

    fallback() external payable {
        revert InvalidCall();
    }
}
