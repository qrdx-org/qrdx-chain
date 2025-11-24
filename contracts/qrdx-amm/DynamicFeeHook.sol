// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IHooks.sol";
import "./IPoolManager.sol";

/**
 * @title DynamicFeeHook
 * @notice Example hook implementing dynamic fees based on volatility
 * 
 * Adjusts swap fees dynamically based on recent price movements.
 * Higher volatility results in higher fees to compensate LPs for increased risk.
 */
contract DynamicFeeHook is IHooks {
    IPoolManager public immutable poolManager;
    
    /// @dev Base fee (0.3%)
    uint24 constant BASE_FEE = 3000;
    
    /// @dev Maximum fee (1%)
    uint24 constant MAX_FEE = 10000;
    
    /// @dev Volatility tracking window (number of swaps)
    uint256 constant VOLATILITY_WINDOW = 10;
    
    struct VolatilityData {
        uint256[] priceChanges;
        uint256 currentIndex;
        uint256 swapCount;
    }
    
    /// @notice Volatility data by pool ID
    mapping(bytes32 => VolatilityData) public volatilityData;
    
    /// @notice Current dynamic fee by pool ID
    mapping(bytes32 => uint24) public dynamicFees;
    
    event FeeUpdated(bytes32 indexed poolId, uint24 newFee, uint256 volatility);
    
    constructor(address _poolManager) {
        poolManager = IPoolManager(_poolManager);
    }
    
    /**
     * @notice Get current dynamic fee for a pool
     * @param poolKey The pool key
     * @return fee The current fee in basis points (1/1000000)
     */
    function getCurrentFee(IPoolManager.PoolKey calldata poolKey) external view returns (uint24 fee) {
        bytes32 poolId = poolManager.getPoolId(poolKey);
        fee = dynamicFees[poolId];
        if (fee == 0) fee = BASE_FEE;
    }
    
    // ============ Hook Implementations ============
    
    function beforeInitialize(
        address,
        IPoolManager.PoolKey calldata key,
        uint160
    ) external override returns (bytes4) {
        bytes32 poolId = poolManager.getPoolId(key);
        
        // Initialize with base fee
        dynamicFees[poolId] = BASE_FEE;
        
        // Initialize volatility tracking
        volatilityData[poolId].priceChanges = new uint256[](VOLATILITY_WINDOW);
        
        return IHooks.beforeInitialize.selector;
    }
    
    function afterInitialize(
        address,
        IPoolManager.PoolKey calldata,
        uint160,
        int24
    ) external pure override returns (bytes4) {
        return IHooks.afterInitialize.selector;
    }
    
    function beforeSwap(
        address,
        IPoolManager.PoolKey calldata key,
        IPoolManager.SwapParams calldata
    ) external override returns (bytes4) {
        bytes32 poolId = poolManager.getPoolId(key);
        IPoolManager.Pool memory pool = poolManager.getPool(key);
        
        // Record current price for volatility calculation
        VolatilityData storage data = volatilityData[poolId];
        
        // Store current price (simplified - in production would track price changes)
        uint256 currentPrice = uint256(pool.sqrtPriceX96);
        
        if (data.swapCount > 0) {
            uint256 lastIndex = (data.currentIndex + VOLATILITY_WINDOW - 1) % VOLATILITY_WINDOW;
            uint256 lastPrice = data.priceChanges[lastIndex];
            
            if (lastPrice > 0) {
                // Calculate price change
                uint256 priceChange = currentPrice > lastPrice
                    ? ((currentPrice - lastPrice) * 10000) / lastPrice
                    : ((lastPrice - currentPrice) * 10000) / lastPrice;
                
                // Store price change
                data.priceChanges[data.currentIndex] = priceChange;
                data.currentIndex = (data.currentIndex + 1) % VOLATILITY_WINDOW;
            }
        }
        
        return IHooks.beforeSwap.selector;
    }
    
    function afterSwap(
        address,
        IPoolManager.PoolKey calldata key,
        IPoolManager.SwapParams calldata,
        int256,
        int256
    ) external override returns (bytes4) {
        bytes32 poolId = poolManager.getPoolId(key);
        IPoolManager.Pool memory pool = poolManager.getPool(key);
        VolatilityData storage data = volatilityData[poolId];
        
        data.swapCount++;
        
        // Update fee after sufficient data collected
        if (data.swapCount >= VOLATILITY_WINDOW) {
            uint256 volatility = calculateVolatility(poolId);
            uint24 newFee = calculateDynamicFee(volatility);
            
            if (newFee != dynamicFees[poolId]) {
                dynamicFees[poolId] = newFee;
                emit FeeUpdated(poolId, newFee, volatility);
            }
        }
        
        // Store current price
        uint256 lastIndex = (data.currentIndex + VOLATILITY_WINDOW - 1) % VOLATILITY_WINDOW;
        data.priceChanges[lastIndex] = uint256(pool.sqrtPriceX96);
        
        return IHooks.afterSwap.selector;
    }
    
    function beforeModifyPosition(
        address,
        IPoolManager.PoolKey calldata,
        IPoolManager.ModifyPositionParams calldata
    ) external pure override returns (bytes4) {
        return IHooks.beforeModifyPosition.selector;
    }
    
    function afterModifyPosition(
        address,
        IPoolManager.PoolKey calldata,
        IPoolManager.ModifyPositionParams calldata,
        int256,
        int256
    ) external pure override returns (bytes4) {
        return IHooks.afterModifyPosition.selector;
    }
    
    // ============ Internal Functions ============
    
    /**
     * @notice Calculate average volatility from recent price changes
     * @param poolId The pool identifier
     * @return volatility The average volatility in basis points
     */
    function calculateVolatility(bytes32 poolId) internal view returns (uint256 volatility) {
        VolatilityData storage data = volatilityData[poolId];
        uint256 sum = 0;
        
        for (uint256 i = 0; i < VOLATILITY_WINDOW; i++) {
            sum += data.priceChanges[i];
        }
        
        volatility = sum / VOLATILITY_WINDOW;
    }
    
    /**
     * @notice Calculate dynamic fee based on volatility
     * @param volatility The current volatility
     * @return fee The calculated fee
     */
    function calculateDynamicFee(uint256 volatility) internal pure returns (uint24 fee) {
        // Base fee + volatility adjustment
        // Higher volatility = higher fee
        // Cap at MAX_FEE
        
        fee = BASE_FEE + uint24((volatility * 100)); // Scale volatility to fee
        
        if (fee > MAX_FEE) {
            fee = MAX_FEE;
        }
    }
}
