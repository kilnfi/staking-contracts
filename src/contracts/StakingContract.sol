//SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.10;

import "./libs/State.sol";
import "./libs/UintLib.sol";
import "./libs/BytesLib.sol";

import "./interfaces/IDepositContract.sol";

/// @title Ethereum Staking Contract
/// @author SkillZ
/// @notice You can use this contract to store validator keys and have users fund them and trigger deposits.
contract StakingContract {
    error AlreadyInitialized();
    error Unauthorized();
    error InvalidCall();
    error InvalidArgument();
    error UnsortedIndexes();
    error InvalidPublicKeys();
    error InvalidSignatures();
    error InvalidMessageValue();
    error FundedValidatorDeletionAttempt();
    error DepositFailure();
    error NoOperators();
    error NotEnoughValidators();

    uint256 public constant SIGNATURE_LENGTH = 96;
    uint256 public constant PUBLIC_KEY_LENGTH = 48;
    uint256 public constant DEPOSIT_SIZE = 32 ether;

    event Deposit(address indexed caller, address indexed withdrawer, bytes publicKey, bytes32 publicKeyRoot);

    function _primes() internal pure returns (uint8[54] memory primes) {
        primes = [
            2,
            3,
            5,
            7,
            11,
            13,
            17,
            19,
            23,
            29,
            31,
            37,
            41,
            43,
            47,
            53,
            59,
            61,
            67,
            71,
            73,
            79,
            83,
            89,
            97,
            101,
            103,
            107,
            109,
            113,
            127,
            131,
            137,
            139,
            149,
            151,
            157,
            163,
            167,
            173,
            179,
            181,
            191,
            193,
            197,
            199,
            211,
            223,
            227,
            229,
            233,
            239,
            241,
            251
        ];
    }

    error InvalidValidatorCount();

    function _getClosestPrimeAbove(uint8 _count) internal pure returns (uint8) {
        uint8[54] memory primes = _primes();
        for (uint256 i; i < primes.length; ) {
            if (primes[i] >= _count) {
                return primes[i];
            }
            unchecked {
                ++i;
            }
        }
        revert InvalidValidatorCount();
    }

    /// @notice Ensures an initialisation call has been called only once per _version value
    /// @param _version The current initialisation value
    modifier init(uint256 _version) {
        if (_version != State.getVersion() + 1) {
            revert AlreadyInitialized();
        }

        State.setVersion(_version);
        _;
    }

    /// @notice Ensures that the caller is the admin
    modifier onlyAdmin() {
        if (msg.sender != State.getAdmin()) {
            revert Unauthorized();
        }

        _;
    }

    /// @notice Ensures that the caller is the admin
    modifier onlyOperator(uint256 _operatorIndex) {
        if (msg.sender != State.getOperators().value[_operatorIndex].operator) {
            revert Unauthorized();
        }

        _;
    }

    /// @notice Initializes version 1 of Staking Contract
    /// @param _admin Address of the admin allowed to change the operator and admin
    /// @param _depositContract Address of the Deposit Contract
    /// @param _withdrawalCredentials Withdrawal Credentials to apply to all provided keys upon deposit
    function initialize_1(
        address _admin,
        address _depositContract,
        bytes32 _withdrawalCredentials
    ) external init(1) {
        State.setWithdrawalCredentials(_withdrawalCredentials);
        State.setDepositContract(_depositContract);
        State.setAdmin(_admin);
    }

    function getAdmin() external view returns (address) {
        return State.getAdmin();
    }

    function setAdmin(address _newAdmin) external onlyAdmin {
        State.setAdmin(_newAdmin);
    }

    function addOperator(address _operatorAddress) external onlyAdmin returns (uint256) {
        State.OperatorsSlot storage operators = State.getOperators();
        State.OperatorInfo memory newOperator;
        newOperator.operator = _operatorAddress;
        operators.value.push(newOperator);
        return operators.value.length - 1;
    }

    function setOperatorLimit(uint256 _operatorIndex, uint256 _limit) external onlyAdmin {
        State.OperatorsSlot storage operators = State.getOperators();
        State.OperatorSelectionInfo memory operatorInfo = State.getOperatorInfo(_operatorIndex);
        uint256 oldAvailableCount = operatorInfo.availableKeys;
        uint256 newAvailableCount = 0;
        uint256 cap = _min(_limit, operators.value[_operatorIndex].publicKeys.length);

        if (cap <= operatorInfo.funded) {
            State.setOperatorInfo(_operatorIndex, 0, operatorInfo.funded);
            newAvailableCount = 0;
        } else {
            State.setOperatorInfo(_operatorIndex, uint32(cap - operatorInfo.funded), operatorInfo.funded);
            newAvailableCount = uint32(cap - operatorInfo.funded);
        }

        if (oldAvailableCount != newAvailableCount) {
            if (oldAvailableCount > newAvailableCount) {
                State.setTotalAvailableValidators(
                    State.getTotalAvailableValidators() - (oldAvailableCount - newAvailableCount)
                );
            } else {
                State.setTotalAvailableValidators(
                    State.getTotalAvailableValidators() + (newAvailableCount - oldAvailableCount)
                );
            }
        }

        operators.value[_operatorIndex].limit = _limit;
    }

    function getOperator(uint256 _operatorIndex)
        external
        view
        returns (
            address operatorAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available
        )
    {
        State.OperatorsSlot storage operators = State.getOperators();
        if (_operatorIndex < operators.value.length) {
            State.OperatorSelectionInfo memory operatorInfo = State.getOperatorInfo(_operatorIndex);

            (operatorAddress, limit, keys) = (
                operators.value[_operatorIndex].operator,
                operators.value[_operatorIndex].limit,
                operators.value[_operatorIndex].publicKeys.length
            );
            (funded, available) = (operatorInfo.funded, operatorInfo.availableKeys);
        }
    }

    function _min(uint256 _a, uint256 _b) internal pure returns (uint256) {
        if (_a < _b) {
            return _a;
        }
        return _b;
    }

    function addValidators(
        uint256 _operatorIndex,
        uint256 _keyCount,
        bytes calldata _publicKeys,
        bytes calldata _signatures
    ) external onlyOperator(_operatorIndex) {
        if (_keyCount == 0) {
            revert InvalidArgument();
        }

        if (_publicKeys.length % PUBLIC_KEY_LENGTH != 0 || _publicKeys.length / PUBLIC_KEY_LENGTH != _keyCount) {
            revert InvalidPublicKeys();
        }

        if (_signatures.length % SIGNATURE_LENGTH != 0 || _signatures.length / SIGNATURE_LENGTH != _keyCount) {
            revert InvalidSignatures();
        }

        State.OperatorsSlot storage operators = State.getOperators();

        for (uint256 i; i < _keyCount; ) {
            bytes memory publicKey = BytesLib.slice(_publicKeys, i * PUBLIC_KEY_LENGTH, PUBLIC_KEY_LENGTH);
            bytes memory signature = BytesLib.slice(_signatures, i * SIGNATURE_LENGTH, SIGNATURE_LENGTH);

            operators.value[_operatorIndex].publicKeys.push(publicKey);
            operators.value[_operatorIndex].signatures.push(signature);

            unchecked {
                ++i;
            }
        }

        State.OperatorSelectionInfo memory operatorInfo = State.getOperatorInfo(_operatorIndex);
        uint256 oldAvailableCount = operatorInfo.availableKeys;
        uint256 newAvailableCount = 0;
        uint256 cap = _min(operators.value[_operatorIndex].limit, operators.value[_operatorIndex].publicKeys.length);

        if (cap <= operatorInfo.funded) {
            State.setOperatorInfo(_operatorIndex, 0, operatorInfo.funded);
            newAvailableCount = 0;
        } else {
            State.setOperatorInfo(_operatorIndex, uint32(cap - operatorInfo.funded), operatorInfo.funded);
            newAvailableCount = uint32(cap - operatorInfo.funded);
        }

        if (oldAvailableCount != newAvailableCount) {
            State.setTotalAvailableValidators(
                State.getTotalAvailableValidators() + (newAvailableCount - oldAvailableCount)
            );
        }
    }

    function removeValidators(uint256 _operatorIndex, uint256[] calldata _indexes)
        external
        onlyOperator(_operatorIndex)
    {
        if (_indexes.length == 0) {
            revert InvalidArgument();
        }

        State.OperatorSelectionInfo memory operatorInfo = State.getOperatorInfo(_operatorIndex);
        State.OperatorsSlot storage operators = State.getOperators();

        for (uint256 i; i < _indexes.length; ) {
            if (i > 0 && _indexes[i] >= _indexes[i - 1]) {
                revert UnsortedIndexes();
            }

            if (_indexes[i] < operatorInfo.funded) {
                revert FundedValidatorDeletionAttempt();
            }

            if (_indexes[i] == operators.value[_operatorIndex].publicKeys.length - 1) {
                operators.value[_operatorIndex].publicKeys.pop();
                operators.value[_operatorIndex].signatures.pop();
            } else {
                operators.value[_operatorIndex].publicKeys[_indexes[i]] = operators.value[_operatorIndex].publicKeys[
                    operators.value[_operatorIndex].publicKeys.length - 1
                ];
                operators.value[_operatorIndex].publicKeys.pop();
                operators.value[_operatorIndex].signatures[_indexes[i]] = operators.value[_operatorIndex].signatures[
                    operators.value[_operatorIndex].signatures.length - 1
                ];
                operators.value[_operatorIndex].signatures.pop();
            }

            unchecked {
                ++i;
            }
        }

        uint256 oldAvailableCount = operatorInfo.availableKeys;
        uint256 newAvailableCount = 0;
        uint256 cap = _min(operators.value[_operatorIndex].limit, operators.value[_operatorIndex].publicKeys.length);

        if (cap <= operatorInfo.funded) {
            State.setOperatorInfo(_operatorIndex, 0, operatorInfo.funded);
            newAvailableCount = 0;
        } else {
            State.setOperatorInfo(_operatorIndex, uint32(cap - operatorInfo.funded), operatorInfo.funded);
            newAvailableCount = uint32(cap - operatorInfo.funded);
        }

        if (oldAvailableCount != newAvailableCount) {
            State.setTotalAvailableValidators(
                State.getTotalAvailableValidators() - (oldAvailableCount - newAvailableCount)
            );
        }
    }

    struct ValidatorDetails {
        uint8 used;
        uint128 operatorIndex;
        uint120 count;
    }

    function _useBest(
        uint256 alphaIndex,
        uint256 alphaTemporaryDeposits,
        uint256 betaIndex,
        uint256 betaTemporaryDeposits
    ) internal view returns (int256 operatorIndex) {
        State.OperatorSelectionInfo memory alphaOsi = State.getOperatorInfo(alphaIndex);
        State.OperatorSelectionInfo memory betaOsi = State.getOperatorInfo(betaIndex);
        if (alphaOsi.availableKeys == 0) {
            if (betaOsi.availableKeys == 0) {
                return -1;
            } else {
                return int256(betaIndex);
            }
        } else if (betaOsi.availableKeys == 0) {
            if (alphaOsi.availableKeys == 0) {
                return -1;
            } else {
                return int256(alphaIndex);
            }
        } else {
            if ((alphaOsi.funded + alphaTemporaryDeposits) > (betaOsi.funded + betaTemporaryDeposits)) {
                return int256(betaIndex);
            } else {
                return int256(alphaIndex);
            }
        }
    }

    function _depositValidatorsOfOperator(
        uint256 _operatorIndex,
        uint256 _validatorCount,
        address _withdrawer
    ) internal {
        State.OperatorsSlot storage operators = State.getOperators();
        State.OperatorInfo storage operator = operators.value[_operatorIndex];
        State.OperatorSelectionInfo memory osi = State.getOperatorInfo(_operatorIndex);
        bytes32 withdrawalCredentials = State.getWithdrawalCredentials();

        for (uint256 i = osi.funded; i < osi.funded + _validatorCount; ) {
            bytes memory publicKey = operator.publicKeys[i];
            bytes memory signature = operator.signatures[i];
            _depositValidator(publicKey, signature, withdrawalCredentials);
            bytes32 pubkeyRoot = sha256(BytesLib.pad64(publicKey));
            State.getWithdrawers().value[pubkeyRoot] = _withdrawer;
            emit Deposit(msg.sender, _withdrawer, publicKey, pubkeyRoot);
            unchecked {
                ++i;
            }
        }

        State.setOperatorInfo(
            _operatorIndex,
            uint32(osi.availableKeys - _validatorCount),
            uint32(osi.funded + _validatorCount)
        );
    }

    function _depositValidator(
        bytes memory _publicKey,
        bytes memory _signature,
        bytes32 _withdrawalCredentials
    ) internal {
        bytes32 pubkeyRoot = sha256(BytesLib.pad64(_publicKey));
        bytes32 signatureRoot = sha256(
            abi.encodePacked(
                sha256(BytesLib.slice(_signature, 0, 64)),
                sha256(BytesLib.pad64(BytesLib.slice(_signature, 64, SIGNATURE_LENGTH - 64)))
            )
        );

        uint256 depositAmount = DEPOSIT_SIZE / 1000000000 wei;
        assert(depositAmount * 1000000000 wei == DEPOSIT_SIZE);

        bytes32 depositDataRoot = sha256(
            abi.encodePacked(
                sha256(abi.encodePacked(pubkeyRoot, _withdrawalCredentials)),
                sha256(abi.encodePacked(Uint256Lib.toLittleEndian64(depositAmount), signatureRoot))
            )
        );

        uint256 targetBalance = address(this).balance - DEPOSIT_SIZE;

        IDepositContract(State.getDepositContract()).deposit{value: DEPOSIT_SIZE}(
            _publicKey,
            abi.encodePacked(_withdrawalCredentials),
            _signature,
            depositDataRoot
        );

        if (address(this).balance != targetBalance) {
            revert DepositFailure();
        }
    }

    function _getTemporaryDeposits(uint256 _operatorIndex, ValidatorDetails[] memory _vd)
        internal
        pure
        returns (uint256)
    {
        for (uint256 i; i < _vd.length; ) {
            if (_vd[i].used == 1) {
                if (_vd[i].operatorIndex == _operatorIndex) {
                    return _vd[i].count;
                }
            } else {
                return 0;
            }
            unchecked {
                ++i;
            }
        }
        return 0;
    }

    function _deposit(address _withdrawer) internal {
        if (msg.value == 0 || msg.value % DEPOSIT_SIZE != 0) {
            revert InvalidMessageValue();
        }
        uint256 totalAvailableValidators = State.getTotalAvailableValidators();
        uint256 depositCount = msg.value / DEPOSIT_SIZE;
        if (depositCount > totalAvailableValidators) {
            revert NotEnoughValidators();
        }
        State.OperatorsSlot storage operators = State.getOperators();
        if (operators.value.length == 0) {
            revert NoOperators();
        } else if (operators.value.length == 1) {
            _depositValidatorsOfOperator(0, depositCount, _withdrawer);
        } else if (operators.value.length == 2) {
            State.OperatorSelectionInfo memory oneOsi = State.getOperatorInfo(0);
            State.OperatorSelectionInfo memory twoOsi = State.getOperatorInfo(1);

            uint256 oneDepositCount = depositCount / 2;
            uint256 twoDepositCount = depositCount / 2;
            if (oneDepositCount + twoDepositCount != depositCount) {
                ++oneDepositCount;
            }
            if (oneDepositCount > oneOsi.availableKeys) {
                twoDepositCount = depositCount - oneOsi.availableKeys;
                oneDepositCount = oneOsi.availableKeys;
            } else if (twoDepositCount > twoOsi.availableKeys) {
                oneDepositCount = depositCount - twoOsi.availableKeys;
                twoDepositCount = twoOsi.availableKeys;
            }

            if (oneDepositCount > 0) {
                _depositValidatorsOfOperator(0, oneDepositCount, _withdrawer);
            }
            if (twoDepositCount > 0) {
                _depositValidatorsOfOperator(1, twoDepositCount, _withdrawer);
            }
        } else {
            uint256 operatorCount = operators.value.length;
            uint8 optimusPrime = _getClosestPrimeAbove(uint8(operatorCount));

            bytes32 blockHash = blockhash(block.number); // weak random number as it's not a security issue
            uint256 alphaIndex = uint8(blockHash[0]) % operatorCount;
            uint256 skip = uint8(blockHash[1]) % optimusPrime;
            if (skip == 0) {
                ++skip;
            }
            uint256 betaIndex = (alphaIndex + skip) % optimusPrime;

            ValidatorDetails[] memory vd = new ValidatorDetails[](depositCount);

            uint256 reservedValidators = 0;

            while (depositCount > 0) {
                if (alphaIndex == betaIndex) {
                    betaIndex = (betaIndex + skip) % optimusPrime;
                }

                if (betaIndex < operatorCount) {
                    uint256 alphaTmpd = _getTemporaryDeposits(alphaIndex, vd);
                    uint256 betaTmpd = _getTemporaryDeposits(betaIndex, vd);
                    int256 operatorIndex = _useBest(alphaIndex, alphaTmpd, betaIndex, betaTmpd);

                    if (operatorIndex >= 0) {
                        for (uint256 i; i < vd.length; ) {
                            if (vd[i].used == 1) {
                                if (uint256(vd[i].operatorIndex) == uint256(operatorIndex)) {
                                    ++vd[i].count;
                                    break;
                                }
                            } else {
                                vd[i].used = 1;
                                vd[i].operatorIndex = uint128(int128(operatorIndex));
                                vd[i].count = 1;
                                break;
                            }
                            unchecked {
                                ++i;
                            }
                        }
                        --depositCount;
                        ++reservedValidators;
                    }
                }

                betaIndex = (betaIndex + skip) % optimusPrime;
            }

            for (uint256 i; i < vd.length; ) {
                if (vd[i].used == 1) {
                    _depositValidatorsOfOperator(vd[i].operatorIndex, vd[i].count, _withdrawer);
                } else {
                    break;
                }
                unchecked {
                    ++i;
                }
            }

            State.setTotalAvailableValidators(totalAvailableValidators - reservedValidators);
        }
    }

    /// @notice Explicit deposit method
    /// @dev A multiple of 32 ETH should be sent
    /// @param _withdrawer The withdrawer address
    function deposit(address _withdrawer) external payable {
        _deposit(_withdrawer);
    }

    /// @notice Implicit deposit method
    /// @dev A multiple of 32 ETH should be sent
    /// @dev The withdrawer is set to the message sender address
    receive() external payable {
        _deposit(msg.sender);
    }

    /// @notice Fallback detection
    /// @dev Fails on any call that fallbacks
    fallback() external payable {
        revert InvalidCall();
    }

    function getWithdrawer(bytes calldata _publicKey) external view returns (address) {
        bytes32 pubkeyRoot = sha256(BytesLib.pad64(_publicKey));
        State.WithdrawersSlot storage withdrawers = State.getWithdrawers();

        return withdrawers.value[pubkeyRoot];
    }

    function setWithdrawer(bytes calldata _publicKey, address _newWithdrawer) external {
        bytes32 pubkeyRoot = sha256(BytesLib.pad64(_publicKey));
        State.WithdrawersSlot storage withdrawers = State.getWithdrawers();

        if (withdrawers.value[pubkeyRoot] != msg.sender) {
            revert Unauthorized();
        }

        withdrawers.value[pubkeyRoot] = _newWithdrawer;
    }
}
