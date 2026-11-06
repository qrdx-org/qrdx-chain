// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title QRDXLockbox — the source-chain side of the QRDX consensus bridge (docs/BRIDGE.md)
/// @notice Users lock ERC-20 tokens here, naming a QRDX recipient. Each deposit gets the next id
///         and a record in storage, `deposits[id]`: the hash of what it was. QRDX mints it either
///         when validators holding two thirds of the stake attest it, or when anyone proves the
///         record against a finalized head of this chain the validators attested (a storage proof
///         from `eth_getProof`): the validators then vouch for one state root, not for each
///         deposit. A withdrawal burned on QRDX is released here by the custodian, at most once.
/// @dev    QRDX validators sign with ML-DSA-65, which this chain cannot verify, so releases are
///         the custodian's: deploy it as a multisig. Deposits record only what was received, so a
///         fee-on-transfer token is credited what actually arrived.
///         A deposit QRDX never mints (its token is not bridged, QRDX refuses its recipient, or it
///         was not counted within the network's deposit window) can be refunded once, after
///         `refundDelay`, and only as it was made: the whole amount, back to its depositor. QRDX
///         never counts a deposit past its window, so a refund cannot meet a mint
///         (docs/BRIDGE.md "Refunds").
interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract QRDXLockbox {
    /// @notice A lock: QRDX mints `amount` of the bridged token to `recipient` (deposit `depositId`).
    event Deposit(
        uint256 indexed depositId,
        address indexed token,
        address indexed from,
        uint256 amount,
        string recipient,
        uint256 time
    );
    /// @notice The custodian released QRDX withdrawal `withdrawalId`.
    event Released(uint256 indexed withdrawalId, address indexed token, address indexed to, uint256 amount);
    /// @notice The custodian returned deposit `depositId` to its depositor.
    event Refunded(uint256 indexed depositId, address indexed token, address indexed to, uint256 amount);
    event DepositsPaused(bool paused);
    event CustodyOffered(address indexed next);
    event CustodyAccepted(address indexed custodian);

    uint256 public constant MAX_RECIPIENT_LENGTH = 128;

    // Storage layout matters: QRDX proves `deposits` entries by their slot (DEPOSITS_SLOT in
    // qrdx/exchange/bridge.py, checked against this contract's compiled layout).
    address public custodian; // slot 0
    address public pendingCustodian; // slot 1
    bool public depositsPaused; // slot 1
    mapping(uint256 => bool) public released; // slot 2
    uint256 public depositCount; // slot 3
    /// @notice id → keccak256(abi.encode(token, from, amount, recipient, time)).
    mapping(uint256 => bytes32) public deposits; // slot 4
    mapping(uint256 => bool) public refunded; // slot 5
    uint256 private _entered = 1; // slot 6

    /// @notice How long after a deposit it may be refunded: longer than QRDX's deposit window.
    uint256 public immutable refundDelay;

    modifier onlyCustodian() {
        require(msg.sender == custodian, "QRDXLockbox: not the custodian");
        _;
    }

    modifier nonReentrant() {
        require(_entered == 1, "QRDXLockbox: reentrant call");
        _entered = 2;
        _;
        _entered = 1;
    }

    constructor(address custodian_, uint256 refundDelay_) {
        require(custodian_ != address(0), "QRDXLockbox: no custodian");
        require(refundDelay_ >= 1 days, "QRDXLockbox: refund delay under a day");
        custodian = custodian_;
        refundDelay = refundDelay_;
        emit CustodyAccepted(custodian_);
    }

    /// @notice What `deposits[id]` holds for a deposit.
    function depositRecord(
        address token,
        address from,
        uint256 amount,
        string memory recipient,
        uint256 time
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(token, from, amount, recipient, time));
    }

    /// @notice Lock `amount` of `token` for `recipient` on QRDX (a 0xPQ… or 0x… address).
    ///         Only tokens the QRDX network lists in its BRIDGE_ASSETS are minted there: check
    ///         `bridge_getAssets` first — anything else is refunded after `refundDelay`.
    function deposit(address token, uint256 amount, string calldata recipient)
        external
        nonReentrant
        returns (uint256 depositId)
    {
        require(!depositsPaused, "QRDXLockbox: deposits paused");
        require(amount > 0, "QRDXLockbox: zero amount");
        uint256 length = bytes(recipient).length;
        require(length > 0 && length <= MAX_RECIPIENT_LENGTH, "QRDXLockbox: bad recipient");
        uint256 before = IERC20(token).balanceOf(address(this));
        _call(token, abi.encodeWithSelector(IERC20.transferFrom.selector, msg.sender, address(this), amount));
        uint256 received = IERC20(token).balanceOf(address(this)) - before;
        require(received > 0, "QRDXLockbox: nothing received");
        depositId = ++depositCount;
        deposits[depositId] = depositRecord(token, msg.sender, received, recipient, block.timestamp);
        emit Deposit(depositId, token, msg.sender, received, recipient, block.timestamp);
    }

    /// @notice Release QRDX withdrawal `withdrawalId` (`bridge_getWithdrawals`): `amount` is in
    ///         the token's base units (the QRDX amount × 10^decimals).
    function release(uint256 withdrawalId, address token, address to, uint256 amount)
        external
        onlyCustodian
        nonReentrant
    {
        require(!released[withdrawalId], "QRDXLockbox: already released");
        require(to != address(0) && amount > 0, "QRDXLockbox: bad release");
        released[withdrawalId] = true;
        _call(token, abi.encodeWithSelector(IERC20.transfer.selector, to, amount));
        emit Released(withdrawalId, token, to, amount);
    }

    /// @notice Refund deposit `depositId`, which QRDX will never mint, exactly as it was made:
    ///         the whole amount back to its depositor, once, after `refundDelay`.
    function refund(
        uint256 depositId,
        address token,
        address from,
        uint256 amount,
        string calldata recipient,
        uint256 time
    ) external onlyCustodian nonReentrant {
        require(deposits[depositId] != bytes32(0), "QRDXLockbox: no such deposit");
        require(
            deposits[depositId] == depositRecord(token, from, amount, recipient, time),
            "QRDXLockbox: not this deposit"
        );
        require(!refunded[depositId], "QRDXLockbox: already refunded");
        require(block.timestamp > time + refundDelay, "QRDXLockbox: too early to refund");
        refunded[depositId] = true;
        _call(token, abi.encodeWithSelector(IERC20.transfer.selector, from, amount));
        emit Refunded(depositId, token, from, amount);
    }

    function setDepositsPaused(bool paused) external onlyCustodian {
        depositsPaused = paused;
        emit DepositsPaused(paused);
    }

    /// @notice Two-step custody hand-over: the next custodian must accept.
    function offerCustody(address next) external onlyCustodian {
        pendingCustodian = next;
        emit CustodyOffered(next);
    }

    function acceptCustody() external {
        require(msg.sender == pendingCustodian && msg.sender != address(0), "QRDXLockbox: not offered");
        custodian = msg.sender;
        pendingCustodian = address(0);
        emit CustodyAccepted(msg.sender);
    }

    /// @dev An ERC-20 call that tolerates tokens returning nothing, and fails on `false`.
    function _call(address token, bytes memory data) private {
        require(token.code.length > 0, "QRDXLockbox: not a contract");
        (bool ok, bytes memory ret) = token.call(data);
        require(ok && (ret.length == 0 || abi.decode(ret, (bool))), "QRDXLockbox: token call failed");
    }
}
