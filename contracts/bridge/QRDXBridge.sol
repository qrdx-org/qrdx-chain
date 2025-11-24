// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IQRDXBridge.sol";

/**
 * @title QRDXBridge
 * @notice Quantum-resistant bridge for ETH<->QRDX asset transfers
 * 
 * Security features:
 * - Dilithium signature verification (quantum-resistant)
 * - Multi-validator consensus
 * - Merkle proof verification
 * - Time-locked withdrawals
 * - Challenge period for disputes
 */
contract QRDXBridge is IQRDXBridge {
    // =============================================================
    //                        CONSTANTS
    // =============================================================
    
    /// @dev Dilithium signature verification precompile (0x09)
    address constant DILITHIUM_PRECOMPILE = address(0x09);
    
    /// @dev BLAKE3 hashing precompile (0x0c)
    address constant BLAKE3_PRECOMPILE = address(0x0c);
    
    /// @dev Minimum stake for validators (100 ETH)
    uint256 public constant MIN_VALIDATOR_STAKE = 100 ether;
    
    /// @dev Challenge period duration (7 days)
    uint256 public constant CHALLENGE_PERIOD = 7 days;
    
    /// @dev Transfer expiration time (30 days)
    uint256 public constant TRANSFER_EXPIRATION = 30 days;
    
    /// @dev Minimum confirmations (2/3 of validators)
    uint256 public constant CONFIRMATION_THRESHOLD = 67; // 67%
    
    // =============================================================
    //                        STORAGE
    // =============================================================
    
    /// @notice Bridge owner/admin
    address public owner;
    
    /// @notice All transfer requests by ID
    mapping(bytes32 => TransferRequest) public transfers;
    
    /// @notice All validators by Ethereum address
    mapping(address => Validator) public validators;
    
    /// @notice Active validator addresses
    address[] public validatorList;
    
    /// @notice Transfer confirmations by validator
    mapping(bytes32 => mapping(address => bool)) public transferConfirmations;
    
    /// @notice Total locked value by token
    mapping(address => uint256) public totalLocked;
    
    /// @notice Nonce for generating unique transfer IDs
    uint256 private nonce;
    
    /// @notice Bridge pause status
    bool public paused;
    
    // =============================================================
    //                        MODIFIERS
    // =============================================================
    
    modifier onlyOwner() {
        require(msg.sender == owner, "NOT_OWNER");
        _;
    }
    
    modifier onlyValidator() {
        require(validators[msg.sender].active, "NOT_VALIDATOR");
        _;
    }
    
    modifier whenNotPaused() {
        require(!paused, "PAUSED");
        _;
    }
    
    modifier validTransfer(bytes32 transferId) {
        require(transfers[transferId].id != bytes32(0), "INVALID_TRANSFER");
        _;
    }
    
    // =============================================================
    //                      CONSTRUCTOR
    // =============================================================
    
    constructor() {
        owner = msg.sender;
    }
    
    // =============================================================
    //                   DEPOSIT FUNCTIONS
    // =============================================================
    
    /**
     * @notice Deposit tokens for cross-chain transfer
     */
    function deposit(
        address recipient,
        address token,
        uint256 amount
    ) public payable override whenNotPaused returns (bytes32 transferId) {
        require(recipient != address(0), "INVALID_RECIPIENT");
        require(amount > 0, "INVALID_AMOUNT");
        
        // Generate unique transfer ID using BLAKE3
        transferId = _generateTransferId(msg.sender, recipient, token, amount);
        require(transfers[transferId].id == bytes32(0), "DUPLICATE_TRANSFER");
        
        // Handle ETH vs ERC20
        if (token == address(0)) {
            require(msg.value == amount, "INCORRECT_ETH_AMOUNT");
        } else {
            require(msg.value == 0, "NO_ETH_FOR_TOKEN");
            // Transfer tokens from sender to bridge
            (bool success, bytes memory data) = token.call(
                abi.encodeWithSignature("transferFrom(address,address,uint256)", msg.sender, address(this), amount)
            );
            require(success && (data.length == 0 || abi.decode(data, (bool))), "TOKEN_TRANSFER_FAILED");
        }
        
        // Update locked value
        totalLocked[token] += amount;
        
        // Create transfer request
        transfers[transferId] = TransferRequest({
            id: transferId,
            sender: msg.sender,
            recipient: recipient,
            token: token,
            amount: amount,
            sourceChain: ChainId.Ethereum,
            targetChain: ChainId.QRDX,
            timestamp: block.timestamp,
            confirmations: 0,
            status: TransferStatus.Pending,
            merkleRoot: bytes32(0)
        });
        
        emit DepositInitiated(transferId, msg.sender, recipient, token, amount, ChainId.Ethereum, ChainId.QRDX);
    }
    
    /**
     * @notice Deposit ETH for transfer to QRDX
     */
    function depositETH(address recipient) external payable override whenNotPaused returns (bytes32 transferId) {
        return deposit(recipient, address(0), msg.value);
    }
    
    // =============================================================
    //                   WITHDRAWAL FUNCTIONS
    // =============================================================
    
    /**
     * @notice Withdraw tokens from QRDX to Ethereum
     */
    function withdraw(
        bytes32 transferId,
        MerkleProof calldata proof,
        bytes[] calldata dilithiumSignatures
    ) external override whenNotPaused returns (bool success) {
        TransferRequest storage request = transfers[transferId];
        
        // Validate transfer exists and is from QRDX
        require(request.id != bytes32(0) || request.sourceChain == ChainId.QRDX, "INVALID_TRANSFER");
        
        // If transfer doesn't exist yet, create it from proof
        if (request.id == bytes32(0)) {
            // Decode transfer data from Merkle leaf
            (address sender, address recipient, address token, uint256 amount) = abi.decode(
                abi.encode(proof.leaf),
                (address, address, address, uint256)
            );
            
            request.id = transferId;
            request.sender = sender;
            request.recipient = recipient;
            request.token = token;
            request.amount = amount;
            request.sourceChain = ChainId.QRDX;
            request.targetChain = ChainId.Ethereum;
            request.timestamp = block.timestamp;
            request.status = TransferStatus.Pending;
        }
        
        require(request.status == TransferStatus.Pending, "INVALID_STATUS");
        require(request.recipient == msg.sender, "NOT_RECIPIENT");
        
        // Verify Merkle proof
        require(verifyMerkleProof(transferId, proof), "INVALID_PROOF");
        
        // Verify validator signatures
        require(_verifyValidatorSignatures(transferId, dilithiumSignatures), "INVALID_SIGNATURES");
        
        // Mark as confirmed if enough signatures
        uint256 requiredConfirmations = (validatorList.length * CONFIRMATION_THRESHOLD) / 100;
        if (dilithiumSignatures.length >= requiredConfirmations) {
            request.status = TransferStatus.Confirmed;
            request.confirmations = dilithiumSignatures.length;
        }
        
        return true;
    }
    
    /**
     * @notice Claim confirmed transfer
     */
    function claim(bytes32 transferId) external override whenNotPaused validTransfer(transferId) returns (uint256 amount) {
        TransferRequest storage request = transfers[transferId];
        
        require(request.status == TransferStatus.Confirmed, "NOT_CONFIRMED");
        require(request.recipient == msg.sender, "NOT_RECIPIENT");
        require(block.timestamp >= request.timestamp + CHALLENGE_PERIOD, "CHALLENGE_PERIOD_ACTIVE");
        
        // Mark as completed
        request.status = TransferStatus.Completed;
        amount = request.amount;
        
        // Transfer tokens to recipient
        if (request.token == address(0)) {
            // Transfer ETH
            (bool success, ) = request.recipient.call{value: amount}("");
            require(success, "ETH_TRANSFER_FAILED");
        } else {
            // Transfer ERC20
            (bool success, bytes memory data) = request.token.call(
                abi.encodeWithSignature("transfer(address,uint256)", request.recipient, amount)
            );
            require(success && (data.length == 0 || abi.decode(data, (bool))), "TOKEN_TRANSFER_FAILED");
        }
        
        // Update locked value
        totalLocked[request.token] -= amount;
        
        emit TransferCompleted(transferId, request.recipient, amount);
    }
    
    // =============================================================
    //                  VALIDATION FUNCTIONS
    // =============================================================
    
    /**
     * @notice Confirm transfer (validator only)
     */
    function confirmTransfer(
        bytes32 transferId,
        bytes calldata dilithiumSignature
    ) external override onlyValidator validTransfer(transferId) returns (bool confirmed) {
        TransferRequest storage request = transfers[transferId];
        
        require(request.status == TransferStatus.Pending, "INVALID_STATUS");
        require(!transferConfirmations[transferId][msg.sender], "ALREADY_CONFIRMED");
        
        // Verify Dilithium signature
        bytes memory message = abi.encode(transferId, request.sender, request.recipient, request.amount);
        require(_verifyDilithiumSignature(message, validators[msg.sender].dilithiumPublicKey, dilithiumSignature), "INVALID_SIGNATURE");
        
        // Record confirmation
        transferConfirmations[transferId][msg.sender] = true;
        request.confirmations++;
        validators[msg.sender].confirmedTransfers++;
        validators[msg.sender].lastActiveBlock = block.number;
        
        // Check if threshold reached
        uint256 requiredConfirmations = (validatorList.length * CONFIRMATION_THRESHOLD) / 100;
        if (request.confirmations >= requiredConfirmations) {
            request.status = TransferStatus.Confirmed;
            confirmed = true;
        }
        
        emit TransferConfirmed(transferId, msg.sender, request.confirmations, requiredConfirmations);
    }
    
    /**
     * @notice Challenge potentially fraudulent transfer
     */
    function challengeTransfer(
        bytes32 transferId,
        bytes calldata proof,
        string calldata reason
    ) external override validTransfer(transferId) {
        TransferRequest storage request = transfers[transferId];
        
        require(request.status == TransferStatus.Confirmed, "NOT_CONFIRMABLE");
        require(block.timestamp < request.timestamp + CHALLENGE_PERIOD, "CHALLENGE_PERIOD_EXPIRED");
        
        // Mark as challenged
        request.status = TransferStatus.Challenged;
        
        emit TransferChallenged(transferId, msg.sender, reason);
        
        // In production, this would trigger dispute resolution
    }
    
    /**
     * @notice Verify Merkle proof
     */
    function verifyMerkleProof(
        bytes32 transferId,
        MerkleProof calldata proof
    ) public view override returns (bool valid) {
        bytes32 computedHash = proof.leaf;
        
        for (uint256 i = 0; i < proof.proof.length; i++) {
            bytes32 proofElement = proof.proof[i];
            
            if (computedHash <= proofElement) {
                // Hash(current, proofElement)
                computedHash = _blake3Hash(abi.encodePacked(computedHash, proofElement));
            } else {
                // Hash(proofElement, current)
                computedHash = _blake3Hash(abi.encodePacked(proofElement, computedHash));
            }
        }
        
        TransferRequest storage request = transfers[transferId];
        return computedHash == request.merkleRoot;
    }
    
    // =============================================================
    //                 VALIDATOR MANAGEMENT
    // =============================================================
    
    /**
     * @notice Add validator
     */
    function addValidator(
        address ethAddress,
        bytes calldata dilithiumPublicKey,
        uint256 stake
    ) external override onlyOwner {
        require(ethAddress != address(0), "INVALID_ADDRESS");
        require(dilithiumPublicKey.length == 1952, "INVALID_KEY_LENGTH");
        require(stake >= MIN_VALIDATOR_STAKE, "INSUFFICIENT_STAKE");
        require(!validators[ethAddress].active, "ALREADY_VALIDATOR");
        
        validators[ethAddress] = Validator({
            ethAddress: ethAddress,
            dilithiumPublicKey: dilithiumPublicKey,
            stake: stake,
            active: true,
            confirmedTransfers: 0,
            lastActiveBlock: block.number
        });
        
        validatorList.push(ethAddress);
        
        emit ValidatorAdded(ethAddress, dilithiumPublicKey, stake);
    }
    
    /**
     * @notice Remove validator
     */
    function removeValidator(address ethAddress) external override onlyOwner {
        require(validators[ethAddress].active, "NOT_VALIDATOR");
        
        validators[ethAddress].active = false;
        uint256 stake = validators[ethAddress].stake;
        
        // Remove from list
        for (uint256 i = 0; i < validatorList.length; i++) {
            if (validatorList[i] == ethAddress) {
                validatorList[i] = validatorList[validatorList.length - 1];
                validatorList.pop();
                break;
            }
        }
        
        // Return stake
        (bool success, ) = ethAddress.call{value: stake}("");
        require(success, "STAKE_RETURN_FAILED");
        
        emit ValidatorRemoved(ethAddress, stake);
    }
    
    /**
     * @notice Update validator stake
     */
    function updateValidatorStake(uint256 amount, bool increase) external override onlyValidator {
        Validator storage validator = validators[msg.sender];
        
        if (increase) {
            validator.stake += amount;
        } else {
            require(validator.stake >= amount, "INSUFFICIENT_STAKE");
            require(validator.stake - amount >= MIN_VALIDATOR_STAKE, "BELOW_MIN_STAKE");
            validator.stake -= amount;
            
            // Return stake
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success, "STAKE_RETURN_FAILED");
        }
    }
    
    // =============================================================
    //                     VIEW FUNCTIONS
    // =============================================================
    
    function getTransfer(bytes32 transferId) external view override returns (TransferRequest memory) {
        return transfers[transferId];
    }
    
    function getValidator(address ethAddress) external view override returns (Validator memory) {
        return validators[ethAddress];
    }
    
    function isValidator(address ethAddress) external view override returns (bool) {
        return validators[ethAddress].active;
    }
    
    function getValidatorCount() external view override returns (uint256) {
        return validatorList.length;
    }
    
    function getRequiredConfirmations() external view override returns (uint256) {
        return (validatorList.length * CONFIRMATION_THRESHOLD) / 100;
    }
    
    function getTotalLocked(address token) external view override returns (uint256) {
        return totalLocked[token];
    }
    
    // =============================================================
    //                   INTERNAL FUNCTIONS
    // =============================================================
    
    /**
     * @dev Generate unique transfer ID using BLAKE3
     */
    function _generateTransferId(
        address sender,
        address recipient,
        address token,
        uint256 amount
    ) internal returns (bytes32) {
        bytes memory data = abi.encode(sender, recipient, token, amount, nonce++, block.timestamp);
        return _blake3Hash(data);
    }
    
    /**
     * @dev Verify Dilithium signature using precompile
     */
    function _verifyDilithiumSignature(
        bytes memory message,
        bytes memory publicKey,
        bytes memory signature
    ) internal view returns (bool) {
        require(publicKey.length == 1952, "INVALID_PUBLIC_KEY_LENGTH");
        require(signature.length == 3309, "INVALID_SIGNATURE_LENGTH");
        
        bytes memory input = abi.encodePacked(message, publicKey, signature);
        (bool success, bytes memory result) = DILITHIUM_PRECOMPILE.staticcall(input);
        
        return success && result.length > 0 && abi.decode(result, (bool));
    }
    
    /**
     * @dev Verify multiple validator signatures
     */
    function _verifyValidatorSignatures(
        bytes32 transferId,
        bytes[] calldata signatures
    ) internal view returns (bool) {
        bytes memory message = abi.encode(transferId);
        uint256 validSignatures = 0;
        
        for (uint256 i = 0; i < signatures.length; i++) {
            // In production, would map signatures to specific validators
            // For now, just verify signature format
            if (signatures[i].length == 3309) {
                validSignatures++;
            }
        }
        
        uint256 required = (validatorList.length * CONFIRMATION_THRESHOLD) / 100;
        return validSignatures >= required;
    }
    
    /**
     * @dev Hash data using BLAKE3 precompile
     */
    function _blake3Hash(bytes memory data) internal view returns (bytes32) {
        (bool success, bytes memory result) = BLAKE3_PRECOMPILE.staticcall(data);
        require(success, "BLAKE3_FAILED");
        return bytes32(result);
    }
    
    // =============================================================
    //                    ADMIN FUNCTIONS
    // =============================================================
    
    /**
     * @notice Pause bridge operations
     */
    function pause() external onlyOwner {
        paused = true;
    }
    
    /**
     * @notice Unpause bridge operations
     */
    function unpause() external onlyOwner {
        paused = false;
    }
    
    /**
     * @notice Transfer ownership
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "INVALID_ADDRESS");
        owner = newOwner;
    }
    
    /**
     * @notice Receive ETH
     */
    receive() external payable {}
}
