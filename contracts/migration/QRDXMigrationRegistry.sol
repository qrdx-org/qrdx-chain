// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title QRDXMigrationRegistry — bind an Ethereum account to its post-quantum successor
///        (docs/QUANTUM_MIGRATION.md)
/// @notice While ECDSA still holds, an account commits to the QRDX post-quantum account (0xPQ…)
///         that should control it once ECDSA cannot be trusted. The commitment is made with the
///         account's own signature, once, and can never change: an attacker who later breaks the
///         account's key cannot replace it. QRDX proves the commitment against a finalized head
///         of this chain its validators attested (MIGRATION_CLAIM) and binds the post-quantum
///         account as the controller of the account with the same address on QRDX.
/// @dev    Only externally owned accounts register (`msg.sender == tx.origin`): a contract's
///         address on another chain may belong to someone else. Storage layout matters, QRDX
///         proves these slots: `successorOf` at slot 0, `registeredAt` at slot 1.
contract QRDXMigrationRegistry {
    /// @notice account → the 32 bytes of its QRDX post-quantum account (0xPQ + these, in hex).
    mapping(address => bytes32) public successorOf; // slot 0
    /// @notice account → when it registered (block time).
    mapping(address => uint256) public registeredAt; // slot 1

    event Registered(address indexed account, bytes32 indexed successor, uint256 time);

    /// @notice Commit, once and for good, to `successor` (a QRDX 0xPQ… account, its 32 bytes).
    function register(bytes32 successor) external {
        require(msg.sender == tx.origin, "QRDXMigrationRegistry: accounts only, not contracts");
        require(successor != bytes32(0), "QRDXMigrationRegistry: no successor");
        require(successorOf[msg.sender] == bytes32(0), "QRDXMigrationRegistry: already registered");
        successorOf[msg.sender] = successor;
        registeredAt[msg.sender] = block.timestamp;
        emit Registered(msg.sender, successor, block.timestamp);
    }
}
