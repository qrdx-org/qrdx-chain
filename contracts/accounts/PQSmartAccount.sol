// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title PQSmartAccount — a contract account owned by a post-quantum key (docs/PQ_SMART_ACCOUNTS.md)
/// @notice The owner is an ML-DSA-65 key (FIPS 204). It signs batches of calls; anyone may submit
///         them (a relayer, the owner's own account), and the account checks the signature with
///         QRDX's ML-DSA-65 precompile (0x…0500). It also has:
///         - ERC-1271 `isValidSignature`, so applications can check an owner's PQ signature;
///         - session keys: other ML-DSA-65 keys that may call anything but the account itself,
///           until a deadline, spending at most a set amount of QRDX a day;
///         - guardians: accounts that can replace a lost owner key together, after a delay the
///           owner can use to cancel.
/// @dev    Keys are stored as keccak256 hashes and passed in full with each signature: a 1,952-byte
///         key costs ~1.2M gas to store, more than a block's EVM gas. Every signed message is bound
///         to this account and chain (`DOMAIN`), so a signature is never valid elsewhere.
///         Accounts are EIP-1167 proxies of one implementation (PQAccountFactory): a whole
///         account's code does not fit a normal block's gas, a proxy costs well under 100k.
contract PQSmartAccount {
    address internal constant MLDSA_VERIFY = address(0x0500);
    uint256 internal constant PUBLIC_KEY_LENGTH = 1952;
    uint256 internal constant SIGNATURE_LENGTH = 3309;
    bytes4 internal constant ERC1271_MAGIC = 0x1626ba7e;
    bytes32 internal constant DOMAIN = keccak256("QRDX PQSmartAccount v1");
    uint256 public constant MAX_GUARDIANS = 8;

    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    struct Session {
        uint64 validUntil; // unix time; 0: no such session key
        uint128 valuePerDay; // QRDX (wei) it may send a day
        uint64 day; // the day `spent` counts
        uint128 spent;
    }

    bytes32 public ownerKey; // keccak256 of the owner's ML-DSA-65 public key
    uint256 public nonce;
    mapping(bytes32 => Session) public sessions;

    address[] internal _guardians;
    mapping(address => bool) public isGuardian;
    uint256 public guardianThreshold;
    uint256 public recoveryDelay;
    bytes32 public pendingOwnerKey;
    uint256 public recoveryReadyAt; // 0: no recovery pending
    uint256 internal _recoveryRound;
    mapping(uint256 => mapping(address => bool)) internal _approvedRecovery;
    uint256 public recoveryApprovals;

    event Executed(uint256 indexed nonce, bytes32 indexed signerKey, uint256 calls);
    event SessionKeySet(bytes32 indexed key, uint64 validUntil, uint128 valuePerDay);
    event GuardiansSet(address[] guardians, uint256 threshold, uint256 delay);
    event RecoveryApproved(address indexed guardian, bytes32 indexed newOwnerKey, uint256 approvals);
    event RecoveryStarted(bytes32 indexed newOwnerKey, uint256 readyAt);
    event RecoveryCancelled(bytes32 indexed newOwnerKey);
    event OwnerKeyChanged(bytes32 indexed oldKey, bytes32 indexed newKey);

    error BadSignature();
    error BadNonce();
    error Expired();
    error NotSelf();
    error SessionDenied(string why);
    error CallFailed(uint256 index, bytes reason);
    error RecoveryDenied(string why);

    /// @dev The implementation is locked (its owner key has no known preimage). Each account is
    ///      a minimal proxy of it, initialized once by PQAccountFactory.
    constructor() {
        ownerKey = keccak256("PQSmartAccount: implementation, no owner");
    }

    /// @notice Set the owner key of a fresh account (a proxy whose storage is empty). Once.
    function initialize(bytes32 ownerKey_) external {
        require(ownerKey == bytes32(0), "PQSmartAccount: initialized");
        require(ownerKey_ != bytes32(0), "PQSmartAccount: no owner key");
        ownerKey = ownerKey_;
        emit OwnerKeyChanged(bytes32(0), ownerKey_);
    }

    receive() external payable {}

    modifier onlySelf() {
        if (msg.sender != address(this)) revert NotSelf();
        _;
    }

    // ── signatures ───────────────────────────────────────────────────────────────────────

    /// @notice What a key signs for `execute`: this account, chain, nonce, deadline and calls.
    function executeHash(Call[] calldata calls, uint256 nonce_, uint256 validUntil)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(DOMAIN, block.chainid, address(this), nonce_, validUntil, calls));
    }

    function _verify(bytes32 hash, bytes calldata publicKey, bytes calldata signature)
        internal
        view
        returns (bool)
    {
        if (publicKey.length != PUBLIC_KEY_LENGTH || signature.length != SIGNATURE_LENGTH) {
            return false;
        }
        (bool ok, bytes memory out) =
            MLDSA_VERIFY.staticcall(abi.encodePacked(hash, publicKey, signature));
        return ok && out.length == 1 && out[0] == 0x01;
    }

    /// @notice ERC-1271: `signature` is abi.encode(publicKey, mldsaSignature) by the owner over
    ///         keccak256(DOMAIN, chain, this account, hash).
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        (bytes memory publicKey, bytes memory sig) = abi.decode(signature, (bytes, bytes));
        if (keccak256(publicKey) != ownerKey) return 0xffffffff;
        bytes32 bound = keccak256(abi.encode(DOMAIN, block.chainid, address(this), hash));
        if (publicKey.length != PUBLIC_KEY_LENGTH || sig.length != SIGNATURE_LENGTH) return 0xffffffff;
        (bool ok, bytes memory out) = MLDSA_VERIFY.staticcall(abi.encodePacked(bound, publicKey, sig));
        return ok && out.length == 1 && out[0] == 0x01 ? ERC1271_MAGIC : bytes4(0xffffffff);
    }

    // ── execution ────────────────────────────────────────────────────────────────────────

    /// @notice Run `calls`, signed by the owner key or a session key. `nonce_` must be the next
    ///         nonce; `validUntil` (unix time, 0: none) bounds when the signature is good.
    function execute(
        Call[] calldata calls,
        uint256 nonce_,
        uint256 validUntil,
        bytes calldata publicKey,
        bytes calldata signature
    ) external {
        if (nonce_ != nonce) revert BadNonce();
        if (validUntil != 0 && block.timestamp > validUntil) revert Expired();
        bytes32 key = keccak256(publicKey);
        if (!_verify(executeHash(calls, nonce_, validUntil), publicKey, signature)) {
            revert BadSignature();
        }
        if (key != ownerKey) _checkSession(key, calls);
        nonce = nonce_ + 1;
        for (uint256 i = 0; i < calls.length; i++) {
            (bool ok, bytes memory reason) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            if (!ok) revert CallFailed(i, reason);
        }
        emit Executed(nonce_, key, calls.length);
    }

    /// @dev A session key may not call this account (it cannot change keys, guardians or
    ///      sessions) and may spend at most its daily value.
    function _checkSession(bytes32 key, Call[] calldata calls) internal {
        Session storage s = sessions[key];
        if (s.validUntil == 0) revert BadSignature(); // neither the owner nor a session key
        if (block.timestamp > s.validUntil) revert SessionDenied("session expired");
        uint256 value;
        for (uint256 i = 0; i < calls.length; i++) {
            if (calls[i].target == address(this)) revert SessionDenied("a session key cannot administer the account");
            value += calls[i].value;
        }
        uint64 today = uint64(block.timestamp / 1 days);
        if (s.day != today) {
            s.day = today;
            s.spent = 0;
        }
        if (uint256(s.spent) + value > s.valuePerDay) revert SessionDenied("over the daily value");
        s.spent = uint128(uint256(s.spent) + value);
    }

    // ── administration (the owner, through execute) ─────────────────────────────────────

    function setSessionKey(bytes32 key, uint64 validUntil, uint128 valuePerDay) external onlySelf {
        require(key != ownerKey && key != bytes32(0), "PQSmartAccount: bad session key");
        sessions[key] = Session(validUntil, valuePerDay, 0, 0);
        emit SessionKeySet(key, validUntil, valuePerDay);
    }

    function setOwnerKey(bytes32 newKey) external onlySelf {
        require(newKey != bytes32(0), "PQSmartAccount: no owner key");
        emit OwnerKeyChanged(ownerKey, newKey);
        ownerKey = newKey;
        _clearRecovery();
    }

    function setGuardians(address[] calldata guardians, uint256 threshold, uint256 delay)
        external
        onlySelf
    {
        require(guardians.length <= MAX_GUARDIANS, "PQSmartAccount: too many guardians");
        require(
            guardians.length == 0 || (threshold >= 1 && threshold <= guardians.length),
            "PQSmartAccount: bad threshold"
        );
        require(guardians.length == 0 || delay >= 1 days, "PQSmartAccount: delay under a day");
        for (uint256 i = 0; i < _guardians.length; i++) isGuardian[_guardians[i]] = false;
        delete _guardians;
        for (uint256 i = 0; i < guardians.length; i++) {
            require(guardians[i] != address(0) && !isGuardian[guardians[i]], "PQSmartAccount: bad guardian");
            isGuardian[guardians[i]] = true;
            _guardians.push(guardians[i]);
        }
        guardianThreshold = threshold;
        recoveryDelay = delay;
        _clearRecovery();
        emit GuardiansSet(guardians, threshold, delay);
    }

    function guardians() external view returns (address[] memory) {
        return _guardians;
    }

    // ── recovery ─────────────────────────────────────────────────────────────────────────

    /// @notice A guardian approves replacing the owner key with `newOwnerKey`. A different key
    ///         than the one pending starts over. At the threshold the delay starts.
    function approveRecovery(bytes32 newOwnerKey) external {
        if (!isGuardian[msg.sender]) revert RecoveryDenied("not a guardian");
        if (newOwnerKey == bytes32(0)) revert RecoveryDenied("no key");
        if (newOwnerKey != pendingOwnerKey) {
            _clearRecovery();
            pendingOwnerKey = newOwnerKey;
        }
        if (_approvedRecovery[_recoveryRound][msg.sender]) revert RecoveryDenied("already approved");
        _approvedRecovery[_recoveryRound][msg.sender] = true;
        recoveryApprovals += 1;
        emit RecoveryApproved(msg.sender, newOwnerKey, recoveryApprovals);
        if (recoveryApprovals == guardianThreshold) {
            recoveryReadyAt = block.timestamp + recoveryDelay;
            emit RecoveryStarted(newOwnerKey, recoveryReadyAt);
        }
    }

    /// @notice Anyone completes a recovery once its delay has passed.
    function completeRecovery() external {
        if (recoveryReadyAt == 0 || block.timestamp < recoveryReadyAt) {
            revert RecoveryDenied("not ready");
        }
        emit OwnerKeyChanged(ownerKey, pendingOwnerKey);
        ownerKey = pendingOwnerKey;
        _clearRecovery();
    }

    /// @notice The owner (through execute) cancels a pending recovery.
    function cancelRecovery() external onlySelf {
        emit RecoveryCancelled(pendingOwnerKey);
        _clearRecovery();
    }

    function _clearRecovery() internal {
        _recoveryRound += 1;
        pendingOwnerKey = bytes32(0);
        recoveryReadyAt = 0;
        recoveryApprovals = 0;
    }
}


/// @title PQAccountFactory — creates PQSmartAccounts as minimal proxies at predictable addresses
/// @notice `create(ownerKey, salt)` deploys an EIP-1167 proxy of `implementation` with CREATE2 and
///         initializes it in the same transaction, so nobody can take a fresh account first.
///         `predict` gives the address before it exists (fund it, then create it).
contract PQAccountFactory {
    address public immutable implementation;

    event AccountCreated(address indexed account, bytes32 indexed ownerKey, bytes32 salt);

    constructor(address implementation_) {
        implementation = implementation_;
    }

    function _bytecode() internal view returns (bytes memory) {
        return abi.encodePacked(
            hex"3d602d80600a3d3981f3363d3d373d3d3d363d73",
            implementation,
            hex"5af43d82803e903d91602b57fd5bf3"
        );
    }

    function _salt(bytes32 ownerKey, bytes32 salt) internal pure returns (bytes32) {
        return keccak256(abi.encode(ownerKey, salt));
    }

    function predict(bytes32 ownerKey, bytes32 salt) public view returns (address) {
        bytes32 hash = keccak256(
            abi.encodePacked(bytes1(0xff), address(this), _salt(ownerKey, salt), keccak256(_bytecode()))
        );
        return address(uint160(uint256(hash)));
    }

    function create(bytes32 ownerKey, bytes32 salt) external returns (address account) {
        bytes memory code = _bytecode();
        bytes32 s = _salt(ownerKey, salt);
        assembly {
            account := create2(0, add(code, 0x20), mload(code), s)
        }
        require(account != address(0), "PQAccountFactory: exists");
        PQSmartAccount(payable(account)).initialize(ownerKey);
        emit AccountCreated(account, ownerKey, salt);
    }
}
