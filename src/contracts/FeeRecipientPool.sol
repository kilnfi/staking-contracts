//SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.10;

import "../test/console.sol";

contract FeeRecipientPool {

	uint256 FEE_BASE = 1_000_000;

	address owner;
	address feeRecipient;
	uint256 public fee;
	mapping (bytes32 => uint256) public arrivalBalance;
	mapping (bytes32 => bool) public registered;
	uint256 sum;
	uint256 public withdrawn;
	uint256 public memberCount;

	error AlreadyRegistered(bytes32 memberId);
	error NotRegistered(bytes32 memberId);
	error NullWithdraw();
	error WithdrawError(address recipient, bytes reason);
	error Unauthorized(address caller);
	error InvalidFeeArgument(uint256 fee);

	constructor(address _owner, address _feeRecipient, uint256 _fee) {
		owner = _owner;
		feeRecipient = _feeRecipient;
		_setFee(_fee);
	}

	modifier onlyOwner() {
		if (msg.sender != owner) {
			revert Unauthorized(msg.sender);
		}
		_;
	}

	function _setFee(uint256 _fee) internal {
		if (_fee > FEE_BASE) {
			revert InvalidFeeArgument(_fee);
		}
		fee = _fee;
	}

	function setFee(uint256 _fee) external onlyOwner {
		_setFee(_fee);
	}

	function registerMember(bytes32 memberId) external onlyOwner {
		if (registered[memberId] == true) {
			revert AlreadyRegistered(memberId);
		}
		uint256 memberArrivalBalance = address(this).balance + withdrawn;
		arrivalBalance[memberId] = memberArrivalBalance;
		registered[memberId] = true;
		sum += memberArrivalBalance;
		++memberCount;
	}

	function unregisterMember(bytes32 memberId) external onlyOwner {
		if (registered[memberId] == false) {
			revert NotRegistered(memberId);
		}
		sum -= arrivalBalance[memberId];
		arrivalBalance[memberId] = 0;
		registered[memberId] = false;
		--memberCount;
	}

	function withdraw(bytes32 memberId, address recipient) external onlyOwner {
		if (registered[memberId] == false) {
			revert NotRegistered(memberId);
		}
		uint256 totalBalance = address(this).balance + withdrawn;
		uint256 memberArrivalBalance = arrivalBalance[memberId];
		if (totalBalance == memberArrivalBalance) {
			revert NullWithdraw();
		}
		uint256 memberShares = totalBalance - memberArrivalBalance;
		uint256 totalShares = (totalBalance * memberCount) - sum;
		uint256 reward = (address(this).balance * memberShares) / totalShares;
		uint256 withdrawFee = (reward * fee) / FEE_BASE;
		sum += (totalBalance - memberArrivalBalance);
		arrivalBalance[memberId] = totalBalance;
		withdrawn += reward;
		(bool status, bytes memory data) = recipient.call{value: reward - withdrawFee}("");
		if (status == false) {
			revert WithdrawError(recipient, data);
		}
		(status, data) = feeRecipient.call{value: withdrawFee}("");
		if (status == false) {
			revert WithdrawError(recipient, data);
		}
	}

	receive() external payable {

	}

	fallback() external payable {

	}

}
