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
    error NoOperators();
    error InvalidCall();
    error Unauthorized();
    error DepositFailure();
    error InvalidArgument();
    error UnsortedIndexes();
    error InvalidPublicKeys();
    error InvalidSignatures();
    error AlreadyInitialized();
    error InvalidMessageValue();
    error NotEnoughValidators();
    error InvalidValidatorCount();
    error FundedValidatorDeletionAttempt();

    struct ValidatorAllocationCache {
        bool used;
        uint8 operatorIndex;
        uint32 funded;
        uint32 toDeposit;
        uint32 available;
    }

    uint256 public constant SIGNATURE_LENGTH = 96;
    uint256 public constant PUBLIC_KEY_LENGTH = 48;
    uint256 public constant DEPOSIT_SIZE = 32 ether;

    event Deposit(address indexed caller, address indexed withdrawer, bytes publicKey, bytes32 publicKeyRoot);

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

    /// @notice Retrieve system admin
    function getAdmin() external view returns (address) {
        return State.getAdmin();
    }

    /// @notice Retrieve operator details
    /// @param _operatorIndex Operator index
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
            State.ValidatorsFundingInfo memory operatorInfo = State.getValidatorsFundingInfo(_operatorIndex);

            (operatorAddress, limit, keys) = (
                operators.value[_operatorIndex].operator,
                operators.value[_operatorIndex].limit,
                operators.value[_operatorIndex].publicKeys.length
            );
            (funded, available) = (operatorInfo.funded, operatorInfo.availableKeys);
        }
    }

    /// @notice Retrieve withdrawer of public key
    /// @param _publicKey Public Key to check
    function getWithdrawer(bytes calldata _publicKey) external view returns (address) {
        return _getWithdrawer(_publicKey);
    }

    /// @notice Set new admin
    /// @dev Only callable by admin
    /// @param _newAdmin New Administrator address
    function setAdmin(address _newAdmin) external onlyAdmin {
        State.setAdmin(_newAdmin);
    }

    /// @notice Add new operator
    /// @dev Only callable by admin
    /// @param _operatorAddress Operator address allowed to add / remove validators
    function addOperator(address _operatorAddress) external onlyAdmin returns (uint256) {
        State.OperatorsSlot storage operators = State.getOperators();
        State.OperatorInfo memory newOperator;
        newOperator.operator = _operatorAddress;
        operators.value.push(newOperator);
        return operators.value.length - 1;
    }

    /// @notice Set withdrawer for public key
    /// @dev Only callable by current public key withdrawer
    /// @param _publicKey Public key to change withdrawer
    /// @param _newWithdrawer New withdrawer address
    function setWithdrawer(bytes calldata _publicKey, address _newWithdrawer) external {
        bytes32 pubkeyRoot = sha256(BytesLib.pad64(_publicKey));
        State.WithdrawersSlot storage withdrawers = State.getWithdrawers();

        if (withdrawers.value[pubkeyRoot] != msg.sender) {
            revert Unauthorized();
        }

        withdrawers.value[pubkeyRoot] = _newWithdrawer;
    }

    /// @notice Set operator staking limits
    /// @dev Only callable by admin
    /// @param _operatorIndex Operator Index
    /// @param _limit New staking limit
    function setOperatorLimit(uint256 _operatorIndex, uint256 _limit) external onlyAdmin {
        State.OperatorsSlot storage operators = State.getOperators();
        operators.value[_operatorIndex].limit = _limit;
        _updateAvailableValidatorCount(_operatorIndex);
    }

    /// @notice Add new validator public keys and signatures
    /// @dev Only callable by operator
    /// @param _operatorIndex Operator Index
    /// @param _keyCount Number of keys added
    /// @param _publicKeys Concatenated _keyCount public keys
    /// @param _signatures Concatenated _keyCount signatures
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

        _updateAvailableValidatorCount(_operatorIndex);
    }

    /// @notice Remove unfunded validators
    /// @dev Only callable by operator
    /// @dev Indexes should be provided in decreasing order
    /// @param _operatorIndex Operator Index
    /// @param _indexes List of indexes to delete, in decreasing order
    function removeValidators(uint256 _operatorIndex, uint256[] calldata _indexes)
        external
        onlyOperator(_operatorIndex)
    {
        if (_indexes.length == 0) {
            revert InvalidArgument();
        }

        State.ValidatorsFundingInfo memory operatorInfo = State.getValidatorsFundingInfo(_operatorIndex);
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

        _updateAvailableValidatorCount(_operatorIndex);
    }

    function getValidator(uint256 _operatorIndex, uint256 _validatorIndex)
        external
        view
        returns (
            bytes memory publicKey,
            bytes memory signature,
            address withdrawer,
            bool funded
        )
    {
        State.OperatorsSlot storage operators = State.getOperators();
        publicKey = operators.value[_operatorIndex].publicKeys[_validatorIndex];
        signature = operators.value[_operatorIndex].signatures[_validatorIndex];
        withdrawer = _getWithdrawer(publicKey);
        funded = _validatorIndex < State.getValidatorsFundingInfo(_operatorIndex).funded;
    }

    function getAvailableValidatorCount() external view returns (uint256) {
        return State.getTotalAvailableValidators();
    }

    /// ██ ███    ██ ████████ ███████ ██████  ███    ██  █████  ██
    /// ██ ████   ██    ██    ██      ██   ██ ████   ██ ██   ██ ██
    /// ██ ██ ██  ██    ██    █████   ██████  ██ ██  ██ ███████ ██
    /// ██ ██  ██ ██    ██    ██      ██   ██ ██  ██ ██ ██   ██ ██
    /// ██ ██   ████    ██    ███████ ██   ██ ██   ████ ██   ██ ███████

    function _getWithdrawer(bytes memory _publicKey) internal view returns (address) {
        bytes32 pubkeyRoot = sha256(BytesLib.pad64(_publicKey));
        State.WithdrawersSlot storage withdrawers = State.getWithdrawers();

        return withdrawers.value[pubkeyRoot];
    }

    function _updateAvailableValidatorCount(uint256 _operatorIndex) internal {
        State.ValidatorsFundingInfo memory operatorInfo = State.getValidatorsFundingInfo(_operatorIndex);
        State.OperatorsSlot storage operators = State.getOperators();

        uint32 oldAvailableCount = operatorInfo.availableKeys;
        uint32 newAvailableCount = 0;
        uint256 cap = _min(operators.value[_operatorIndex].limit, operators.value[_operatorIndex].publicKeys.length);

        if (cap <= operatorInfo.funded) {
            State.setOperatorInfo(_operatorIndex, 0, operatorInfo.funded);
        } else {
            newAvailableCount = uint32(cap - operatorInfo.funded);
            State.setOperatorInfo(_operatorIndex, uint32(cap - operatorInfo.funded), operatorInfo.funded);
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
    }

    function _depositValidatorsOfOperator(
        uint256 _operatorIndex,
        uint256 _validatorCount,
        address _withdrawer
    ) internal {
        State.OperatorsSlot storage operators = State.getOperators();
        State.OperatorInfo storage operator = operators.value[_operatorIndex];
        State.ValidatorsFundingInfo memory osi = State.getValidatorsFundingInfo(_operatorIndex);
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

    function _depositOnOneOperator(
        address _withdrawer,
        uint256 _depositCount,
        uint256 _totalAvailableValidators
    ) internal {
        _depositValidatorsOfOperator(0, _depositCount, _withdrawer);
        State.setTotalAvailableValidators(_totalAvailableValidators - _depositCount);
    }

    function _depositOnTwoOperators(
        address _withdrawer,
        uint256 _depositCount,
        uint256 _totalAvailableValidators
    ) internal {
        State.ValidatorsFundingInfo memory oneOsi = State.getValidatorsFundingInfo(0);
        State.ValidatorsFundingInfo memory twoOsi = State.getValidatorsFundingInfo(1);

        uint256 oneDepositCount;
        uint256 twoDepositCount;

        // using this tactic to prevent deposits of 1 validator to always go to operator 2
        if (block.number % 2 == 0) {
            oneDepositCount = _depositCount / 2;
            twoDepositCount = _depositCount - oneDepositCount;
        } else {
            twoDepositCount = _depositCount / 2;
            oneDepositCount = _depositCount - twoDepositCount;
        }

        if (oneDepositCount > oneOsi.availableKeys) {
            twoDepositCount = _depositCount - oneOsi.availableKeys;
            oneDepositCount = oneOsi.availableKeys;
        } else if (twoDepositCount > twoOsi.availableKeys) {
            oneDepositCount = _depositCount - twoOsi.availableKeys;
            twoDepositCount = twoOsi.availableKeys;
        }

        if (oneDepositCount > 0) {
            _depositValidatorsOfOperator(0, oneDepositCount, _withdrawer);
        }
        if (twoDepositCount > 0) {
            _depositValidatorsOfOperator(1, twoDepositCount, _withdrawer);
        }
        State.setTotalAvailableValidators(_totalAvailableValidators - (oneDepositCount + twoDepositCount));
    }

    function _getBaseSkip(
        bytes32 blockHash,
        uint256 index,
        uint8 prime
    ) internal pure returns (uint8 base, uint8 skip) {
        base = uint8(blockHash[(index * 2) % 32]) % prime;
        skip = (uint8(blockHash[((index * 2) + 1) % 32]) % (prime - 1)) + 1;
    }

    function _getOperatorFundedCount(uint8 operatorIndex, ValidatorAllocationCache[] memory vd)
        internal
        view
        returns (uint32)
    {
        if (operatorIndex >= vd.length) {
            return 0;
        }
        if (vd[operatorIndex].used == false) {
            State.ValidatorsFundingInfo memory osi = State.getValidatorsFundingInfo(operatorIndex);
            vd[operatorIndex].used = true;
            vd[operatorIndex].funded = osi.funded;
            vd[operatorIndex].available = osi.availableKeys;
        }
        return vd[operatorIndex].funded + vd[operatorIndex].toDeposit;
    }

    function _getOperatorAvailableCount(uint8 operatorIndex, ValidatorAllocationCache[] memory vd)
        internal
        view
        returns (uint32)
    {
        if (operatorIndex >= vd.length) {
            return 0;
        }
        if (vd[operatorIndex].used == false) {
            State.ValidatorsFundingInfo memory osi = State.getValidatorsFundingInfo(operatorIndex);
            vd[operatorIndex].used = true;
            vd[operatorIndex].funded = osi.funded;
            vd[operatorIndex].available = osi.availableKeys;
        }
        return vd[operatorIndex].available - vd[operatorIndex].toDeposit;
    }

    function _assignTemporaryDeposit(uint8 operatorIndex, ValidatorAllocationCache[] memory vd) internal pure {
        vd[operatorIndex].toDeposit += 1;
    }

    function _getBestOperator(
        uint8 alphaIndex,
        uint8 betaIndex,
        bytes32 blockHash,
        ValidatorAllocationCache[] memory vd
    ) internal view returns (uint8) {
        uint256 alphaFundedCount = _getOperatorFundedCount(alphaIndex, vd);
        uint256 betaFundedCount = _getOperatorFundedCount(betaIndex, vd);
        if (alphaFundedCount < betaFundedCount) {
            return alphaIndex;
        } else if (alphaFundedCount > betaFundedCount) {
            return betaIndex;
        } else {
            bool coinToss = (uint8(blockHash[(alphaIndex + betaIndex) % 32]) % 2) == 1;
            if (coinToss == false) {
                return betaIndex;
            } else {
                return alphaIndex;
            }
        }
    }

    function _getElligibleOperators(
        uint8 base,
        uint8 skip,
        uint8 prime,
        ValidatorAllocationCache[] memory vd
    ) internal view returns (uint8, uint8) {
        int16 alphaIndex = -1;
        int16 betaIndex = -1;
        uint8 index = base;
        while (alphaIndex == -1 || betaIndex == -1) {
            if (_getOperatorAvailableCount(index, vd) > 0) {
                if (alphaIndex == -1) {
                    alphaIndex = int8(index);
                } else {
                    betaIndex = int8(index);
                }
            }
            index = (index + skip) % prime;
            if (index == base) {
                betaIndex = alphaIndex;
            }
        }
        return (uint8(int8(alphaIndex)), uint8(int8(betaIndex)));
    }

    function _depositOnThreeOrMoreOperators(
        address _withdrawer,
        uint256 _depositCount,
        uint256 _totalAvailableValidators,
        State.OperatorsSlot storage _operators
    ) internal {
        uint256 operatorCount = _operators.value.length;
        uint8 optimusPrime = _getClosestPrimeAbove(uint8(operatorCount));
        bytes32 blockHash = blockhash(block.number); // weak random number as it's not a security issue

        ValidatorAllocationCache[] memory vd = new ValidatorAllocationCache[](operatorCount);

        for (uint256 index; index < _depositCount; ) {
            // Retrieve base index and skip value based on block hash and current loop index
            (uint8 base, uint8 skip) = _getBaseSkip(blockHash, index, optimusPrime);
            // Retrieve two operator indexes pointing to two (or the same) operator(s) that have at least one available
            // validator key to be used for a deposit. This method takes into account possible pending deposits from
            // previous loop rounds.
            (uint8 alphaIndex, uint8 betaIndex) = _getElligibleOperators(base, skip, optimusPrime, vd);

            if (alphaIndex == betaIndex) {
                // Assign the deposit to the only operator having available keys
                _assignTemporaryDeposit(alphaIndex, vd);
            } else {
                // Assign the deposit to the operator having the lowest amount of funded keys
                _assignTemporaryDeposit(_getBestOperator(alphaIndex, betaIndex, blockHash, vd), vd);
            }

            unchecked {
                ++index;
            }
        }

        // Loop through the cached operator values and deposit any pending deposits
        for (uint256 index; index < vd.length; ) {
            if (vd[index].toDeposit > 0) {
                _depositValidatorsOfOperator(index, vd[index].toDeposit, _withdrawer);
            }
            unchecked {
                ++index;
            }
        }

        State.setTotalAvailableValidators(_totalAvailableValidators - _depositCount);
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
            _depositOnOneOperator(_withdrawer, depositCount, totalAvailableValidators);
        } else if (operators.value.length == 2) {
            _depositOnTwoOperators(_withdrawer, depositCount, totalAvailableValidators);
        } else {
            _depositOnThreeOrMoreOperators(_withdrawer, depositCount, totalAvailableValidators, operators);
        }
    }

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

    function _min(uint256 _a, uint256 _b) internal pure returns (uint256) {
        if (_a < _b) {
            return _a;
        }
        return _b;
    }
}
