// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./PoolTypes.sol";

/**
 * @title IPoolManager
 * @notice Interface for the QRDX AMM Pool Manager (singleton pattern)
 * 
 * The Pool Manager is inspired by Uniswap v4's architecture:
 * - Singleton contract managing all pools
 * - Concentrated liquidity (tick-based)
 * - Hooks system for extensibility
 * - Flash accounting for gas efficiency
 * - Multiple fee tiers
 */
interface IPoolManager {
    
    // =============================================================
    //                          EVENTS
    // =============================================================
    
    event PoolInitialized(
        bytes32 indexed poolId,
        address indexed token0,
        address indexed token1,
        uint24 fee,
        int24 tickSpacing,
        uint160 sqrtPriceX96
    );
    
    event Swap(
        bytes32 indexed poolId,
        address indexed sender,
        int256 amount0,
        int256 amount1,
        uint160 sqrtPriceX96,
        uint128 liquidity,
        int24 tick
    );
    
    event ModifyPosition(
        bytes32 indexed poolId,
        address indexed owner,
        int24 tickLower,
        int24 tickUpper,
        int256 liquidityDelta
    );
    
    event Collect(
        bytes32 indexed poolId,
        address indexed owner,
        int24 tickLower,
        int24 tickUpper,
        uint128 amount0,
        uint128 amount1
    );
    
    // =============================================================
    //                      POOL FUNCTIONS
    // =============================================================
    
    /**
     * @notice Initialize a new pool
     * @param key Pool key
     * @param sqrtPriceX96 Initial sqrt price
     * @return poolId The pool identifier
     */
    function initialize(
        PoolKey calldata key,
        uint160 sqrtPriceX96
    ) external returns (bytes32 poolId);
    
    /**
     * @notice Get pool state
     * @param poolId Pool identifier
     * @return Pool state
     */
    function getPool(bytes32 poolId) external view returns (Pool memory);
    
    /**
     * @notice Get position info
     * @param poolId Pool identifier
     * @param owner Position owner
     * @param tickLower Lower tick
     * @param tickUpper Upper tick
     * @return Position info
     */
    function getPosition(
        bytes32 poolId,
        address owner,
        int24 tickLower,
        int24 tickUpper
    ) external view returns (Position memory);
    
    // =============================================================
    //                      SWAP FUNCTIONS
    // =============================================================
    
    /**
     * @notice Execute a swap
     * @param key Pool key
     * @param params Swap parameters
     * @return delta0 Token0 amount delta
     * @return delta1 Token1 amount delta
     */
    function swap(
        PoolKey calldata key,
        SwapParams calldata params
    ) external returns (int256 delta0, int256 delta1);
    
    // =============================================================
    //                   LIQUIDITY FUNCTIONS
    // =============================================================
    
    /**
     * @notice Modify a liquidity position
     * @param key Pool key
     * @param params Position parameters
     * @return delta0 Token0 amount delta
     * @return delta1 Token1 amount delta
     */
    function modifyPosition(
        PoolKey calldata key,
        ModifyPositionParams calldata params
    ) external returns (int256 delta0, int256 delta1);
    
    /**
     * @notice Collect fees from a position
     * @param key Pool key
     * @param tickLower Lower tick
     * @param tickUpper Upper tick
     * @return amount0 Token0 fees collected
     * @return amount1 Token1 fees collected
     */
    function collect(
        PoolKey calldata key,
        int24 tickLower,
        int24 tickUpper
    ) external returns (uint128 amount0, uint128 amount1);
    
    // =============================================================
    //                     UTILITY FUNCTIONS
    // =============================================================
    
    /**
     * @notice Compute pool ID from key
     * @param key Pool key
     * @return Pool identifier (BLAKE3 hash of key)
     */
    function getPoolId(PoolKey calldata key) external pure returns (bytes32);
}
