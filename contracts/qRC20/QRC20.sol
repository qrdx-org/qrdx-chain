// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IQRC20.sol";

/**
 * @title QRC20
 * @dev Implementation of the qRC20 token standard.
 * 
 * This implementation provides:
 * - Full ERC20 compatibility
 * - Quantum-resistant transfers using Dilithium signatures
 * - BLAKE3 hashing for message construction
 * - Replay protection with nonces
 * 
 * The contract uses QRDX precompiles:
 * - 0x09: Dilithium signature verification
 * - 0x0c: BLAKE3 hashing
 */
contract QRC20 is IQRC20 {
    // =============================================================
    //                          STORAGE
    // =============================================================
    
    // Token metadata
    string private _name;
    string private _symbol;
    uint8 private constant _decimals = 18;
    
    // ERC20 state
    uint256 private _totalSupply;
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    
    // Quantum-resistant state
    mapping(address => bytes) private _publicKeys;
    mapping(address => uint256) private _nonces;
    mapping(address => bool) private _keyRegistered;
    
    // Precompile addresses
    address private constant DILITHIUM_VERIFY = address(0x09);
    address private constant BLAKE3_HASH = address(0x0c);
    
    // Signature constants
    uint256 private constant DILITHIUM_PUBLIC_KEY_SIZE = 1952;
    uint256 private constant DILITHIUM_SIGNATURE_SIZE = 3309;
    
    // =============================================================
    //                        CONSTRUCTOR
    // =============================================================
    
    /**
     * @dev Initializes the token with a name, symbol, and initial supply.
     * 
     * @param name_ Token name
     * @param symbol_ Token symbol
     * @param initialSupply_ Initial token supply (in wei, 18 decimals)
     */
    constructor(string memory name_, string memory symbol_, uint256 initialSupply_) {
        _name = name_;
        _symbol = symbol_;
        
        // Mint initial supply to deployer
        if (initialSupply_ > 0) {
            _balances[msg.sender] = initialSupply_;
            _totalSupply = initialSupply_;
            emit Transfer(address(0), msg.sender, initialSupply_);
        }
    }
    
    // =============================================================
    //                     STANDARD ERC20
    // =============================================================
    
    /// @inheritdoc IQRC20
    function name() external view override returns (string memory) {
        return _name;
    }
    
    /// @inheritdoc IQRC20
    function symbol() external view override returns (string memory) {
        return _symbol;
    }
    
    /// @inheritdoc IQRC20
    function decimals() external pure override returns (uint8) {
        return _decimals;
    }
    
    /// @inheritdoc IQRC20
    function totalSupply() external view override returns (uint256) {
        return _totalSupply;
    }
    
    /// @inheritdoc IQRC20
    function balanceOf(address account) external view override returns (uint256) {
        return _balances[account];
    }
    
    /// @inheritdoc IQRC20
    function transfer(address to, uint256 amount) external override returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }
    
    /// @inheritdoc IQRC20
    function allowance(address owner, address spender) external view override returns (uint256) {
        return _allowances[owner][spender];
    }
    
    /// @inheritdoc IQRC20
    function approve(address spender, uint256 amount) external override returns (bool) {
        _approve(msg.sender, spender, amount);
        return true;
    }
    
    /// @inheritdoc IQRC20
    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        // Check allowance
        uint256 currentAllowance = _allowances[from][msg.sender];
        require(currentAllowance >= amount, "QRC20: insufficient allowance");
        
        // Update allowance (no need to update if max)
        if (currentAllowance != type(uint256).max) {
            unchecked {
                _approve(from, msg.sender, currentAllowance - amount);
            }
        }
        
        // Transfer tokens
        _transfer(from, to, amount);
        return true;
    }
    
    // =============================================================
    //                  QUANTUM-RESISTANT EXTENSIONS
    // =============================================================
    
    /// @inheritdoc IQRC20
    function quantumTransfer(
        address from,
        address to,
        uint256 amount,
        uint256 nonce,
        bytes calldata publicKey,
        bytes calldata signature
    ) external override returns (bool) {
        // Validate input sizes
        require(publicKey.length == DILITHIUM_PUBLIC_KEY_SIZE, "QRC20: invalid public key size");
        require(signature.length == DILITHIUM_SIGNATURE_SIZE, "QRC20: invalid signature size");
        
        // Check nonce
        require(nonce == _nonces[from], "QRC20: invalid nonce");
        
        // Derive address from public key and verify it matches 'from'
        address derivedAddress = _deriveAddress(publicKey);
        require(derivedAddress == from, "QRC20: address mismatch");
        
        // Construct message to verify
        bytes memory message = _constructTransferMessage(from, to, amount, nonce);
        
        // Verify Dilithium signature using precompile 0x09
        bool isValid = _verifyDilithiumSignature(message, publicKey, signature);
        require(isValid, "QRC20: invalid signature");
        
        // Increment nonce to prevent replay
        unchecked {
            _nonces[from]++;
        }
        
        // Register public key if not already registered
        if (!_keyRegistered[from]) {
            _publicKeys[from] = publicKey;
            _keyRegistered[from] = true;
        }
        
        // Execute transfer
        _transfer(from, to, amount);
        
        // Emit quantum transfer event
        emit QuantumTransfer(from, to, amount, publicKey, signature);
        
        return true;
    }
    
    /// @inheritdoc IQRC20
    function nonces(address account) external view override returns (uint256) {
        return _nonces[account];
    }
    
    /// @inheritdoc IQRC20
    function getPublicKey(address account) external view override returns (bytes memory) {
        return _publicKeys[account];
    }
    
    /// @inheritdoc IQRC20
    function registerPublicKey(bytes calldata publicKey) external override returns (bool) {
        require(publicKey.length == DILITHIUM_PUBLIC_KEY_SIZE, "QRC20: invalid public key size");
        require(!_keyRegistered[msg.sender], "QRC20: key already registered");
        
        // Verify that the derived address matches msg.sender
        address derivedAddress = _deriveAddress(publicKey);
        require(derivedAddress == msg.sender, "QRC20: address mismatch");
        
        // Register the public key
        _publicKeys[msg.sender] = publicKey;
        _keyRegistered[msg.sender] = true;
        
        return true;
    }
    
    // =============================================================
    //                     INTERNAL FUNCTIONS
    // =============================================================
    
    /**
     * @dev Internal transfer function.
     * 
     * @param from Source address
     * @param to Destination address
     * @param amount Amount to transfer
     */
    function _transfer(address from, address to, uint256 amount) internal {
        require(from != address(0), "QRC20: transfer from zero address");
        require(to != address(0), "QRC20: transfer to zero address");
        
        uint256 fromBalance = _balances[from];
        require(fromBalance >= amount, "QRC20: insufficient balance");
        
        unchecked {
            _balances[from] = fromBalance - amount;
            _balances[to] += amount;
        }
        
        emit Transfer(from, to, amount);
    }
    
    /**
     * @dev Internal approve function.
     * 
     * @param owner Token owner
     * @param spender Approved spender
     * @param amount Approved amount
     */
    function _approve(address owner, address spender, uint256 amount) internal {
        require(owner != address(0), "QRC20: approve from zero address");
        require(spender != address(0), "QRC20: approve to zero address");
        
        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }
    
    /**
     * @dev Derives an address from a Dilithium public key using BLAKE3.
     * 
     * Uses precompile 0x0c (BLAKE3) to hash the public key, then takes
     * the last 20 bytes as the address (Ethereum-compatible).
     * 
     * @param publicKey Dilithium public key (1,952 bytes)
     * @return address The derived Ethereum address
     */
    function _deriveAddress(bytes calldata publicKey) internal view returns (address) {
        // Call BLAKE3 precompile to hash the public key
        (bool success, bytes memory result) = BLAKE3_HASH.staticcall(publicKey);
        require(success, "QRC20: BLAKE3 precompile failed");
        require(result.length == 32, "QRC20: invalid BLAKE3 output");
        
        // Take last 20 bytes of hash as address
        bytes32 hash = bytes32(result);
        return address(uint160(uint256(hash)));
    }
    
    /**
     * @dev Constructs the message to be signed for a quantum transfer.
     * 
     * Message format: BLAKE3(from || to || amount || nonce || contractAddress)
     * This prevents replay attacks across different tokens and nonces.
     * 
     * @param from Source address
     * @param to Destination address
     * @param amount Transfer amount
     * @param nonce Current nonce
     * @return bytes The message to sign
     */
    function _constructTransferMessage(
        address from,
        address to,
        uint256 amount,
        uint256 nonce
    ) internal view returns (bytes memory) {
        // Encode transfer data
        bytes memory data = abi.encodePacked(from, to, amount, nonce, address(this));
        
        // Hash with BLAKE3
        (bool success, bytes memory result) = BLAKE3_HASH.staticcall(data);
        require(success, "QRC20: BLAKE3 precompile failed");
        
        return result;
    }
    
    /**
     * @dev Verifies a Dilithium signature using precompile 0x09.
     * 
     * @param message The message that was signed
     * @param publicKey The Dilithium public key (1,952 bytes)
     * @param signature The Dilithium signature (3,309 bytes)
     * @return bool True if signature is valid
     */
    function _verifyDilithiumSignature(
        bytes memory message,
        bytes calldata publicKey,
        bytes calldata signature
    ) internal view returns (bool) {
        // Prepare input: message || publicKey || signature
        bytes memory input = abi.encodePacked(message, publicKey, signature);
        
        // Call Dilithium verify precompile
        (bool success, bytes memory result) = DILITHIUM_VERIFY.staticcall(input);
        
        // Precompile returns 1 byte: 0x01 for valid, 0x00 for invalid
        if (!success || result.length != 1) {
            return false;
        }
        
        return result[0] == 0x01;
    }
}
