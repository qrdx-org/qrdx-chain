// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title AddressRegistry
 * @notice Registry for mapping classical 20-byte Ethereum addresses to 32-byte PQ addresses
 * @dev Deployed at canonical address 0x0000000000000000000000000000000000000100
 * 
 * This contract enables the migration from classical secp256k1 addresses to post-quantum
 * Dilithium addresses while maintaining backward compatibility. Users can link their
 * classical address to a PQ address and migrate their assets gradually.
 */
contract AddressRegistry {
    
    // ========== Events ==========
    
    event AddressLinked(
        address indexed classicalAddress,
        bytes32 indexed pqAddress,
        uint256 timestamp
    );
    
    event AddressUnlinked(
        address indexed classicalAddress,
        bytes32 indexed pqAddress,
        uint256 timestamp
    );
    
    event MigrationCompleted(
        address indexed classicalAddress,
        bytes32 indexed pqAddress,
        uint256 timestamp
    );
    
    // ========== State Variables ==========
    
    // Classical address => PQ address
    mapping(address => bytes32) private classicalToPQ;
    
    // PQ address => Classical address
    mapping(bytes32 => address) private pqToClassical;
    
    // Track migration status
    mapping(address => bool) private migrationCompleted;
    
    // Total number of linked addresses
    uint256 public totalLinkedAddresses;
    
    // ========== Errors ==========
    
    error AddressAlreadyLinked(address classicalAddress);
    error AddressNotLinked(address classicalAddress);
    error PQAddressAlreadyUsed(bytes32 pqAddress);
    error InvalidPQAddress();
    error InvalidSignature();
    error InvalidPQPublicKey();
    error UnauthorizedCaller();
    
    // ========== Core Functions ==========
    
    /**
     * @notice Link a classical address to a PQ address
     * @dev Can only be called by the classical address owner with valid PQ signature proof
     * @param pqAddress 32-byte post-quantum address (BLAKE3 hash of Dilithium pubkey)
     * @param pqPubkey Dilithium public key (2592 bytes)
     * @param pqSignature Dilithium signature proving ownership (4595 bytes)
     */
    function linkAddress(
        bytes32 pqAddress,
        bytes memory pqPubkey,
        bytes memory pqSignature
    ) external {
        address classicalAddress = msg.sender;
        
        // Validate inputs
        if (pqAddress == bytes32(0)) {
            revert InvalidPQAddress();
        }
        
        if (classicalToPQ[classicalAddress] != bytes32(0)) {
            revert AddressAlreadyLinked(classicalAddress);
        }
        
        if (pqToClassical[pqAddress] != address(0)) {
            revert PQAddressAlreadyUsed(pqAddress);
        }
        
        // Validate PQ public key size (Dilithium5 = 2592 bytes)
        if (pqPubkey.length != 2592) {
            revert InvalidPQPublicKey();
        }
        
        // Verify PQ signature using internal verification
        // PRODUCTION: This must call Dilithium precompile at 0x10 for security
        // TESTING: Basic validation is performed in _verifyPQSignature below
        bool signatureValid = _verifyPQSignature(
            classicalAddress,
            pqAddress,
            pqPubkey,
            pqSignature
        );
        
        if (!signatureValid) {
            revert InvalidSignature();
        }
        
        // Create bidirectional mapping
        classicalToPQ[classicalAddress] = pqAddress;
        pqToClassical[pqAddress] = classicalAddress;
        
        totalLinkedAddresses++;
        
        emit AddressLinked(classicalAddress, pqAddress, block.timestamp);
    }
    
    /**
     * @notice Unlink a classical address from its PQ address
     * @dev Can only be called by the classical address owner
     */
    function unlinkAddress() external {
        address classicalAddress = msg.sender;
        bytes32 pqAddress = classicalToPQ[classicalAddress];
        
        if (pqAddress == bytes32(0)) {
            revert AddressNotLinked(classicalAddress);
        }
        
        // Remove bidirectional mapping
        delete classicalToPQ[classicalAddress];
        delete pqToClassical[pqAddress];
        delete migrationCompleted[classicalAddress];
        
        totalLinkedAddresses--;
        
        emit AddressUnlinked(classicalAddress, pqAddress, block.timestamp);
    }
    
    /**
     * @notice Mark migration as completed for an address
     * @dev After migration, the classical address should be considered deprecated
     */
    function completeMigration() external {
        address classicalAddress = msg.sender;
        bytes32 pqAddress = classicalToPQ[classicalAddress];
        
        if (pqAddress == bytes32(0)) {
            revert AddressNotLinked(classicalAddress);
        }
        
        migrationCompleted[classicalAddress] = true;
        
        emit MigrationCompleted(classicalAddress, pqAddress, block.timestamp);
    }
    
    // ========== View Functions ==========
    
    /**
     * @notice Get the PQ address linked to a classical address
     * @param classicalAddress The classical 20-byte Ethereum address
     * @return pqAddress The linked 32-byte PQ address (0 if not linked)
     */
    function getLinkedPQAddress(address classicalAddress) 
        external 
        view 
        returns (bytes32 pqAddress) 
    {
        return classicalToPQ[classicalAddress];
    }
    
    /**
     * @notice Get the classical address linked to a PQ address
     * @param pqAddress The 32-byte PQ address
     * @return classicalAddress The linked classical address (0x0 if not linked)
     */
    function getLinkedClassicalAddress(bytes32 pqAddress) 
        external 
        view 
        returns (address classicalAddress) 
    {
        return pqToClassical[pqAddress];
    }
    
    /**
     * @notice Check if an address has completed migration
     * @param classicalAddress The classical address to check
     * @return completed True if migration is complete
     */
    function isMigrationCompleted(address classicalAddress) 
        external 
        view 
        returns (bool completed) 
    {
        return migrationCompleted[classicalAddress];
    }
    
    /**
     * @notice Check if a classical address is linked
     * @param classicalAddress The address to check
     * @return linked True if the address has a PQ mapping
     */
    function isAddressLinked(address classicalAddress) 
        external 
        view 
        returns (bool linked) 
    {
        return classicalToPQ[classicalAddress] != bytes32(0);
    }
    
    /**
     * @notice Check if a PQ address is already in use
     * @param pqAddress The PQ address to check
     * @return inUse True if the PQ address is linked to a classical address
     */
    function isPQAddressUsed(bytes32 pqAddress) 
        external 
        view 
        returns (bool inUse) 
    {
        return pqToClassical[pqAddress] != address(0);
    }
    
    // ========== Internal Functions ==========
    
    /**
     * @notice Verify PQ signature
     * @dev PRODUCTION REQUIREMENT: Must call Dilithium precompile at address 0x10
     * @dev CURRENT: Performs basic size validation only (insecure for production!)
     * @dev Full implementation: (bool success, ) = address(0x10).staticcall(abi.encode(message, pubkey, signature))
     * @param classicalAddress The classical address being linked
     * @param pqAddress The PQ address being linked  
     * @param pqPubkey The Dilithium public key (2592 bytes for ML-DSA-87)
     * @param pqSignature The Dilithium signature (4595 bytes for ML-DSA-87)
     * @return valid True if signature is valid (always true in testing mode!)
     */
    function _verifyPQSignature(
        address classicalAddress,
        bytes32 pqAddress,
        bytes memory pqPubkey,
        bytes memory pqSignature
    ) internal view returns (bool valid) {
        // Message to sign: keccak256(classicalAddress || pqAddress)
        bytes32 message = keccak256(abi.encodePacked(classicalAddress, pqAddress));
        
        // Basic validation for Dilithium5/ML-DSA-87
        if (pqPubkey.length != 2592) return false;
        if (pqSignature.length != 4595 && pqSignature.length != 4627) return false;
        
        // ⚠️ PRODUCTION INTEGRATION REQUIRED ⚠️
        // This contract REQUIRES Dilithium verification precompile at address 0x10
        // 
        // Production implementation must replace the return statement below with:
        //
        // (bool success, bytes memory result) = address(0x10).staticcall(
        //     abi.encode(message, pqPubkey, pqSignature)
        // );
        // require(success, \"Precompile call failed\");
        // return abi.decode(result, (bool));
        //
        // Additionally, verify PQ address = BLAKE3(pqPubkey) using precompile 0x13
        //
        // ⚠️ TESTING MODE: Returns true after size validation (INSECURE!) ⚠️
        // DO NOT deploy to production without precompile integration!
        
        return true;  // ⚠️ REPLACE WITH PRECOMPILE CALL ⚠️
    }
    
    // ========== Admin Functions (Optional) ==========
    
    /**
     * @notice Get total statistics
     * @return total Total number of linked addresses
     */
    function getStats() external view returns (uint256 total) {
        return totalLinkedAddresses;
    }
}
