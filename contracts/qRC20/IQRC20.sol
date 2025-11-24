// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IQRC20
 * @dev Interface for the qRC20 token standard - a quantum-resistant ERC20 extension.
 * 
 * qRC20 is fully compatible with ERC20 but adds quantum-resistant features:
 * - Uses Dilithium (ML-DSA-65) for signature verification via precompile 0x09
 * - Supports BLAKE3 hashing via precompile 0x0c
 * - Maintains ERC20 compatibility for existing tooling
 * 
 * All standard ERC20 functions work as expected. Additional quantum-resistant
 * features are opt-in via extended functions.
 */
interface IQRC20 {
    // =============================================================
    //                          EVENTS
    // =============================================================
    
    /**
     * @dev Emitted when `value` tokens are moved from `from` to `to`.
     * Standard ERC20 Transfer event.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);
    
    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set.
     * Standard ERC20 Approval event.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    /**
     * @dev Emitted when a quantum-resistant signature is verified for a transfer.
     * This extends standard ERC20 with quantum-resistant authentication.
     */
    event QuantumTransfer(
        address indexed from,
        address indexed to,
        uint256 value,
        bytes publicKey,
        bytes signature
    );
    
    // =============================================================
    //                     STANDARD ERC20
    // =============================================================
    
    /**
     * @dev Returns the name of the token.
     */
    function name() external view returns (string memory);
    
    /**
     * @dev Returns the symbol of the token.
     */
    function symbol() external view returns (string memory);
    
    /**
     * @dev Returns the decimals places of the token.
     * Standard is 18 for ERC20.
     */
    function decimals() external view returns (uint8);
    
    /**
     * @dev Returns the total token supply.
     */
    function totalSupply() external view returns (uint256);
    
    /**
     * @dev Returns the token balance of `account`.
     */
    function balanceOf(address account) external view returns (uint256);
    
    /**
     * @dev Moves `amount` tokens from the caller's account to `to`.
     * Returns a boolean value indicating whether the operation succeeded.
     * Emits a {Transfer} event.
     */
    function transfer(address to, uint256 amount) external returns (bool);
    
    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}.
     */
    function allowance(address owner, address spender) external view returns (uint256);
    
    /**
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     * Returns a boolean value indicating whether the operation succeeded.
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 amount) external returns (bool);
    
    /**
     * @dev Moves `amount` tokens from `from` to `to` using the allowance mechanism.
     * `amount` is then deducted from the caller's allowance.
     * Returns a boolean value indicating whether the operation succeeded.
     * Emits a {Transfer} event.
     */
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    
    // =============================================================
    //                  QUANTUM-RESISTANT EXTENSIONS
    // =============================================================
    
    /**
     * @dev Transfers tokens using a Dilithium signature for quantum-resistant authentication.
     * 
     * This function verifies a Dilithium (ML-DSA-65) signature using precompile 0x09,
     * then transfers tokens from the signer's account.
     * 
     * @param from The address to transfer from (derived from publicKey)
     * @param to The address to transfer to
     * @param amount The amount of tokens to transfer
     * @param nonce A unique nonce to prevent replay attacks
     * @param publicKey The Dilithium public key (1,952 bytes)
     * @param signature The Dilithium signature (3,309 bytes)
     * @return bool Success status
     * 
     * Requirements:
     * - `publicKey` must be 1,952 bytes (Dilithium public key)
     * - `signature` must be 3,309 bytes (Dilithium signature)
     * - `from` must match the address derived from `publicKey`
     * - `nonce` must not have been used before
     * - Signature must be valid for the transfer message
     */
    function quantumTransfer(
        address from,
        address to,
        uint256 amount,
        uint256 nonce,
        bytes calldata publicKey,
        bytes calldata signature
    ) external returns (bool);
    
    /**
     * @dev Returns the current nonce for an address.
     * Nonces prevent replay attacks in quantum-resistant transfers.
     * 
     * @param account The address to check
     * @return uint256 The current nonce
     */
    function nonces(address account) external view returns (uint256);
    
    /**
     * @dev Returns the Dilithium public key associated with an address.
     * Returns empty bytes if no key is registered.
     * 
     * @param account The address to check
     * @return bytes The Dilithium public key (1,952 bytes) or empty
     */
    function getPublicKey(address account) external view returns (bytes memory);
    
    /**
     * @dev Registers a Dilithium public key for the caller's address.
     * This enables quantum-resistant operations for the address.
     * 
     * @param publicKey The Dilithium public key (1,952 bytes)
     * @return bool Success status
     * 
     * Requirements:
     * - `publicKey` must be 1,952 bytes
     * - Caller must not have already registered a key
     * - Address must match derived address from publicKey
     */
    function registerPublicKey(bytes calldata publicKey) external returns (bool);
}
