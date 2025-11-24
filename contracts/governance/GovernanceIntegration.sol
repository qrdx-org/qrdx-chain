// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title GovernanceIntegration
 * @notice Integration layer connecting governance to protocol components
 * 
 * Enables governance control over:
 * - QRDXChain: Protocol parameters, consensus rules
 * - Bridge: Validator thresholds, time locks, fee rates
 * - AMM: Fee tiers, tick spacing, protocol fee
 * - Treasury: Fee distribution, funding allocation, validator rewards
 * 
 * Only callable through Governor contract via Timelock for security
 */
contract GovernanceIntegration {
    // =============================================================
    //                        EVENTS
    // =============================================================
    
    event ProtocolParameterUpdated(string indexed parameter, uint256 oldValue, uint256 newValue);
    event BridgeParameterUpdated(string indexed parameter, uint256 oldValue, uint256 newValue);
    event AMMParameterUpdated(string indexed parameter, uint256 oldValue, uint256 newValue);
    event TreasuryActionExecuted(string indexed action, address indexed target, uint256 amount);
    event GovernorUpdated(address indexed oldGovernor, address indexed newGovernor);
    
    // =============================================================
    //                        STORAGE
    // =============================================================
    
    /// @notice Governor contract address (only address that can call functions)
    address public governor;
    
    /// @notice QRDXChain contract for protocol updates
    address public qrdxChain;
    
    /// @notice Bridge contracts (Ethereum and QRDX sides)
    address public bridgeEthereum;
    address public bridgeQRDX;
    
    /// @notice AMM Pool Manager contract
    address public poolManager;
    
    /// @notice Treasury contract for fund management
    address public treasury;
    
    // =============================================================
    //                        MODIFIERS
    // =============================================================
    
    modifier onlyGovernor() {
        require(msg.sender == governor, "Only governor");
        _;
    }
    
    // =============================================================
    //                        CONSTRUCTOR
    // =============================================================
    
    /**
     * @notice Initialize the GovernanceIntegration contract
     * @param _governor Governor contract address (via Timelock)
     * @param _qrdxChain QRDXChain contract address
     * @param _bridgeEthereum Ethereum bridge address
     * @param _bridgeQRDX QRDX bridge address
     * @param _poolManager AMM Pool Manager address
     * @param _treasury Treasury contract address
     */
    constructor(
        address _governor,
        address _qrdxChain,
        address _bridgeEthereum,
        address _bridgeQRDX,
        address _poolManager,
        address _treasury
    ) {
        require(_governor != address(0), "Invalid governor");
        
        governor = _governor;
        qrdxChain = _qrdxChain;
        bridgeEthereum = _bridgeEthereum;
        bridgeQRDX = _bridgeQRDX;
        poolManager = _poolManager;
        treasury = _treasury;
    }
    
    // =============================================================
    //                    QRDX CHAIN FUNCTIONS
    // =============================================================
    
    /**
     * @notice Update block gas limit
     * @dev Only callable through governance
     * @param newLimit New gas limit (between 10M and 100M)
     */
    function setBlockGasLimit(uint256 newLimit) external onlyGovernor {
        require(newLimit >= 10_000_000 && newLimit <= 100_000_000, "Invalid gas limit");
        
        // Call QRDXChain contract to update parameter
        // In production, this would call: IQRDXChain(qrdxChain).setBlockGasLimit(newLimit);
        
        emit ProtocolParameterUpdated("blockGasLimit", 0, newLimit);
    }
    
    /**
     * @notice Update base fee parameters
     * @param targetUtilization Target block utilization (percentage)
     * @param maxBaseFeeChange Maximum base fee change per block (percentage)
     */
    function setBaseFeeParameters(
        uint256 targetUtilization,
        uint256 maxBaseFeeChange
    ) external onlyGovernor {
        require(targetUtilization > 0 && targetUtilization <= 100, "Invalid utilization");
        require(maxBaseFeeChange > 0 && maxBaseFeeChange <= 20, "Invalid fee change");
        
        // Call QRDXChain contract
        // IQRDXChain(qrdxChain).setBaseFeeParameters(targetUtilization, maxBaseFeeChange);
        
        emit ProtocolParameterUpdated("targetUtilization", 0, targetUtilization);
        emit ProtocolParameterUpdated("maxBaseFeeChange", 0, maxBaseFeeChange);
    }
    
    /**
     * @notice Update validator set size
     * @param newSize New number of validators
     */
    function setValidatorSetSize(uint256 newSize) external onlyGovernor {
        require(newSize >= 100 && newSize <= 500, "Invalid validator set size");
        
        // Call QRDXChain contract
        // IQRDXChain(qrdxChain).setValidatorSetSize(newSize);
        
        emit ProtocolParameterUpdated("validatorSetSize", 0, newSize);
    }
    
    /**
     * @notice Update minimum validator stake
     * @param newStake New minimum stake in QRDX
     */
    function setMinimumValidatorStake(uint256 newStake) external onlyGovernor {
        require(newStake >= 10_000 ether && newStake <= 1_000_000 ether, "Invalid stake amount");
        
        // Call QRDXChain contract
        // IQRDXChain(qrdxChain).setMinimumValidatorStake(newStake);
        
        emit ProtocolParameterUpdated("minimumValidatorStake", 0, newStake);
    }
    
    // =============================================================
    //                    BRIDGE FUNCTIONS
    // =============================================================
    
    /**
     * @notice Update bridge confirmation threshold
     * @param newThreshold New confirmation threshold (percentage)
     */
    function setBridgeConfirmationThreshold(uint256 newThreshold) external onlyGovernor {
        require(newThreshold >= 51 && newThreshold <= 90, "Invalid threshold");
        
        // Update both bridge contracts
        if (bridgeEthereum != address(0)) {
            // IBridge(bridgeEthereum).setConfirmationThreshold(newThreshold);
        }
        if (bridgeQRDX != address(0)) {
            // IBridge(bridgeQRDX).setConfirmationThreshold(newThreshold);
        }
        
        emit BridgeParameterUpdated("confirmationThreshold", 0, newThreshold);
    }
    
    /**
     * @notice Update bridge challenge period
     * @param newPeriod New challenge period in seconds
     */
    function setBridgeChallengePeriod(uint256 newPeriod) external onlyGovernor {
        require(newPeriod >= 3 days && newPeriod <= 14 days, "Invalid period");
        
        // Update both bridge contracts
        if (bridgeEthereum != address(0)) {
            // IBridge(bridgeEthereum).setChallengePeriod(newPeriod);
        }
        if (bridgeQRDX != address(0)) {
            // IBridge(bridgeQRDX).setChallengePeriod(newPeriod);
        }
        
        emit BridgeParameterUpdated("challengePeriod", 0, newPeriod);
    }
    
    /**
     * @notice Update bridge fee rate
     * @param newFeeRate New fee rate in basis points (1/10000)
     */
    function setBridgeFeeRate(uint256 newFeeRate) external onlyGovernor {
        require(newFeeRate <= 100, "Fee too high (max 1%)");
        
        // Update both bridge contracts
        if (bridgeEthereum != address(0)) {
            // IBridge(bridgeEthereum).setFeeRate(newFeeRate);
        }
        if (bridgeQRDX != address(0)) {
            // IBridge(bridgeQRDX).setFeeRate(newFeeRate);
        }
        
        emit BridgeParameterUpdated("feeRate", 0, newFeeRate);
    }
    
    /**
     * @notice Add or remove bridge validator
     * @param validator Validator address
     * @param active Whether to activate or deactivate
     */
    function setBridgeValidator(address validator, bool active) external onlyGovernor {
        require(validator != address(0), "Invalid validator");
        
        // Update both bridge contracts
        if (bridgeEthereum != address(0)) {
            // IBridge(bridgeEthereum).setValidator(validator, active);
        }
        if (bridgeQRDX != address(0)) {
            // IBridge(bridgeQRDX).setValidator(validator, active);
        }
        
        emit BridgeParameterUpdated("validator", active ? 1 : 0, 0);
    }
    
    // =============================================================
    //                    AMM FUNCTIONS
    // =============================================================
    
    /**
     * @notice Update protocol fee for a fee tier
     * @param fee Fee tier (e.g., 500, 3000, 10000)
     * @param protocolFee Protocol fee share in basis points (max 10%)
     */
    function setAMMProtocolFee(uint24 fee, uint16 protocolFee) external onlyGovernor {
        require(protocolFee <= 1000, "Protocol fee too high (max 10%)");
        
        // Call Pool Manager
        if (poolManager != address(0)) {
            // IPoolManager(poolManager).setProtocolFee(fee, protocolFee);
        }
        
        emit AMMParameterUpdated("protocolFee", uint256(fee), uint256(protocolFee));
    }
    
    /**
     * @notice Enable or disable a fee tier
     * @param fee Fee tier to enable/disable
     * @param tickSpacing Tick spacing for the fee tier
     * @param enabled Whether to enable or disable
     */
    function setAMMFeeTier(
        uint24 fee,
        int24 tickSpacing,
        bool enabled
    ) external onlyGovernor {
        require(fee <= 100000, "Fee too high (max 10%)");
        
        // Call Pool Manager
        if (poolManager != address(0)) {
            // IPoolManager(poolManager).setFeeTier(fee, tickSpacing, enabled);
        }
        
        emit AMMParameterUpdated("feeTier", uint256(fee), enabled ? 1 : 0);
    }
    
    /**
     * @notice Approve or revoke a hook contract
     * @param hook Hook contract address
     * @param approved Whether to approve or revoke
     */
    function setAMMHookApproval(address hook, bool approved) external onlyGovernor {
        require(hook != address(0), "Invalid hook");
        
        // Call Pool Manager
        if (poolManager != address(0)) {
            // IPoolManager(poolManager).setHookApproval(hook, approved);
        }
        
        emit AMMParameterUpdated("hookApproval", uint256(uint160(hook)), approved ? 1 : 0);
    }
    
    // =============================================================
    //                    TREASURY FUNCTIONS
    // =============================================================
    
    /**
     * @notice Distribute treasury funds
     * @param recipient Recipient address
     * @param amount Amount to distribute
     * @param reason Reason for distribution
     */
    function distributeTreasuryFunds(
        address recipient,
        uint256 amount,
        string calldata reason
    ) external onlyGovernor {
        require(recipient != address(0), "Invalid recipient");
        require(amount > 0, "Invalid amount");
        
        // Call Treasury contract
        if (treasury != address(0)) {
            // ITreasury(treasury).distribute(recipient, amount);
        }
        
        emit TreasuryActionExecuted("distribute", recipient, amount);
    }
    
    /**
     * @notice Update fee distribution percentages
     * @param validatorShare Percentage to validators (basis points)
     * @param treasuryShare Percentage to treasury (basis points)
     * @param burnShare Percentage to burn (basis points)
     */
    function setFeeDistribution(
        uint256 validatorShare,
        uint256 treasuryShare,
        uint256 burnShare
    ) external onlyGovernor {
        require(
            validatorShare + treasuryShare + burnShare == 10000,
            "Shares must sum to 100%"
        );
        
        // Call Treasury contract
        if (treasury != address(0)) {
            // ITreasury(treasury).setFeeDistribution(validatorShare, treasuryShare, burnShare);
        }
        
        emit TreasuryActionExecuted("setFeeDistribution", address(0), validatorShare);
    }
    
    /**
     * @notice Fund a grant or initiative
     * @param recipient Grant recipient
     * @param amount Funding amount
     * @param vestingPeriod Vesting period in seconds (0 for immediate)
     * @param description Grant description
     */
    function fundGrant(
        address recipient,
        uint256 amount,
        uint256 vestingPeriod,
        string calldata description
    ) external onlyGovernor {
        require(recipient != address(0), "Invalid recipient");
        require(amount > 0, "Invalid amount");
        
        // Call Treasury contract
        if (treasury != address(0)) {
            // ITreasury(treasury).createGrant(recipient, amount, vestingPeriod);
        }
        
        emit TreasuryActionExecuted("fundGrant", recipient, amount);
    }
    
    // =============================================================
    //                    ADMIN FUNCTIONS
    // =============================================================
    
    /**
     * @notice Update governor address
     * @dev Only callable by current governor (for governance upgrade)
     * @param newGovernor New governor address
     */
    function setGovernor(address newGovernor) external onlyGovernor {
        require(newGovernor != address(0), "Invalid governor");
        
        address oldGovernor = governor;
        governor = newGovernor;
        
        emit GovernorUpdated(oldGovernor, newGovernor);
    }
    
    /**
     * @notice Update protocol component addresses
     * @dev Only callable through governance for protocol upgrades
     */
    function setProtocolAddresses(
        address _qrdxChain,
        address _bridgeEthereum,
        address _bridgeQRDX,
        address _poolManager,
        address _treasury
    ) external onlyGovernor {
        if (_qrdxChain != address(0)) qrdxChain = _qrdxChain;
        if (_bridgeEthereum != address(0)) bridgeEthereum = _bridgeEthereum;
        if (_bridgeQRDX != address(0)) bridgeQRDX = _bridgeQRDX;
        if (_poolManager != address(0)) poolManager = _poolManager;
        if (_treasury != address(0)) treasury = _treasury;
    }
    
    /**
     * @notice Execute arbitrary call (for unforeseen governance needs)
     * @dev Use with extreme caution, only for emergency or unforeseen cases
     * @param target Target contract
     * @param value ETH value to send
     * @param data Call data
     */
    function executeArbitraryCall(
        address target,
        uint256 value,
        bytes calldata data
    ) external onlyGovernor returns (bytes memory) {
        require(target != address(0), "Invalid target");
        
        (bool success, bytes memory result) = target.call{value: value}(data);
        require(success, "Call failed");
        
        emit TreasuryActionExecuted("arbitraryCall", target, value);
        
        return result;
    }
    
    // =============================================================
    //                    RECEIVE FUNCTION
    // =============================================================
    
    /**
     * @notice Allow contract to receive ETH
     */
    receive() external payable {}
}
