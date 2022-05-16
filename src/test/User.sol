//SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.10;

contract User {}

contract UserFactory {
	function n(uint256 _salt) external returns (address) {
		return address(new User{salt: bytes32(_salt)}());
	}
}
