// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title QRDXLockbox — the source-chain side of the QRDX consensus bridge (docs/BRIDGE.md)
/// @notice Users lock ERC-20 tokens here, naming a QRDX recipient. QRDX validators read the
///         `Deposit` events up to this chain's finalized block and attest them; once validators
///         holding two thirds of the stake agree, QRDX mints the bridged token to the recipient.
///         A withdrawal burned on QRDX is released here by the custodian, at most once per id.
/// @dev    QRDX validators sign with Dilithium, which this chain cannot verify, so releases are
///         the custodian's: deploy it as a multisig. Deposits only emit what was received, so a
///         fee-on-transfer token is credited what actually arrived.
interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract QRDXLockbox {
    /// @notice A lock: QRDX validators mint `amount` of the bridged token to `recipient`.
    event Deposit(address indexed token, address indexed from, uint256 amount, string recipient);
    /// @notice The custodian released QRDX withdrawal `withdrawalId`.
    event Released(uint256 indexed withdrawalId, address indexed token, address indexed to, uint256 amount);
    event DepositsPaused(bool paused);
    event CustodyOffered(address indexed next);
    event CustodyAccepted(address indexed custodian);

    uint256 public constant MAX_RECIPIENT_LENGTH = 128;

    address public custodian;
    address public pendingCustodian;
    bool public depositsPaused;
    mapping(uint256 => bool) public released;

    uint256 private _entered = 1;

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

    constructor(address custodian_) {
        require(custodian_ != address(0), "QRDXLockbox: no custodian");
        custodian = custodian_;
        emit CustodyAccepted(custodian_);
    }

    /// @notice Lock `amount` of `token` for `recipient` on QRDX (a 0xPQ… or 0x… address).
    ///         Only tokens the QRDX network lists in its BRIDGE_ASSETS are minted there: check
    ///         `bridge_getAssets` first — anything else stays locked until the custodian returns it.
    function deposit(address token, uint256 amount, string calldata recipient) external nonReentrant {
        require(!depositsPaused, "QRDXLockbox: deposits paused");
        require(amount > 0, "QRDXLockbox: zero amount");
        uint256 length = bytes(recipient).length;
        require(length > 0 && length <= MAX_RECIPIENT_LENGTH, "QRDXLockbox: bad recipient");
        uint256 before = IERC20(token).balanceOf(address(this));
        _call(token, abi.encodeWithSelector(IERC20.transferFrom.selector, msg.sender, address(this), amount));
        uint256 received = IERC20(token).balanceOf(address(this)) - before;
        require(received > 0, "QRDXLockbox: nothing received");
        emit Deposit(token, msg.sender, received, recipient);
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
