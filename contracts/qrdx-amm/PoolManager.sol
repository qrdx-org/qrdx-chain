// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IPoolManager.sol";
import "./IHooks.sol";
import "./TickMath.sol";
import "./SqrtPriceMath.sol";

/**
 * @title PoolManager
 * @notice Singleton contract managing all QRDX AMM pools
 * 
 * Implements concentrated liquidity with tick-based pricing.
 * Uses quantum-resistant BLAKE3 hashing for pool identifiers.
 * Supports extensible hooks for custom pool behavior.
 */
contract PoolManager is IPoolManager {
    using TickMath for int24;
    using SqrtPriceMath for uint160;
    
    /// @dev BLAKE3 precompile address for pool ID generation
    address constant BLAKE3_PRECOMPILE = address(0x0c);
    
    /// @dev Minimum liquidity locked in pool on initialization
    uint128 constant MIN_LIQUIDITY = 1000;
    
    /// @dev Maximum fee: 100% (1,000,000 = 100%)
    uint24 constant MAX_FEE = 1000000;
    
    /// @notice All pools by pool ID
    mapping(bytes32 => Pool) public pools;
    
    /// @notice All positions by pool ID and position owner
    mapping(bytes32 => mapping(address => mapping(int24 => mapping(int24 => Position)))) public positions;
    
    /// @notice Tick liquidity tracking
    mapping(bytes32 => mapping(int24 => TickInfo)) internal ticks;
    
    /// @dev Reentrancy lock
    uint256 private locked = 1;
    
    struct TickInfo {
        uint128 liquidityGross;
        int128 liquidityNet;
        uint256 feeGrowthOutside0X128;
        uint256 feeGrowthOutside1X128;
        bool initialized;
    }
    
    modifier lock() {
        require(locked == 1, "LOCKED");
        locked = 2;
        _;
        locked = 1;
    }
    
    /**
     * @notice Initialize a new pool with starting price
     * @param key The pool key identifying token pair and parameters
     * @param sqrtPriceX96 The initial sqrt price (Q64.96)
     * @return poolId The unique pool identifier
     */
    function initialize(
        PoolKey calldata key,
        uint160 sqrtPriceX96
    ) external override lock returns (bytes32 poolId) {
        // Validate parameters
        require(key.token0 < key.token1, "TOKEN_ORDER");
        require(key.fee <= MAX_FEE, "FEE_TOO_HIGH");
        require(sqrtPriceX96 >= TickMath.MIN_SQRT_RATIO && sqrtPriceX96 < TickMath.MAX_SQRT_RATIO, "PRICE_BOUNDS");
        
        // Calculate pool ID using BLAKE3 (quantum-resistant)
        poolId = getPoolId(key);
        
        // Check pool doesn't exist
        require(pools[poolId].sqrtPriceX96 == 0, "ALREADY_INITIALIZED");
        
        // Get initial tick
        int24 tick = TickMath.getTickAtSqrtRatio(sqrtPriceX96);
        
        // Call beforeInitialize hook if present
        if (key.hooks != address(0)) {
            bytes4 selector = IHooks(key.hooks).beforeInitialize(msg.sender, key, sqrtPriceX96);
            require(selector == IHooks.beforeInitialize.selector, "HOOK_FAILED");
        }
        
        // Initialize pool state
        pools[poolId] = Pool({
            sqrtPriceX96: sqrtPriceX96,
            tick: tick,
            liquidity: 0,
            feeGrowthGlobal0X128: 0,
            feeGrowthGlobal1X128: 0
        });
        
        // Call afterInitialize hook if present
        if (key.hooks != address(0)) {
            bytes4 selector = IHooks(key.hooks).afterInitialize(msg.sender, key, sqrtPriceX96, tick);
            require(selector == IHooks.afterInitialize.selector, "HOOK_FAILED");
        }
        
        emit PoolInitialized(poolId, key.token0, key.token1, key.fee, tick, sqrtPriceX96);
    }
    
    /**
     * @notice Execute a swap
     * @param key The pool key
     * @param params The swap parameters
     * @return amount0 The delta of token0
     * @return amount1 The delta of token1
     */
    function swap(
        PoolKey calldata key,
        SwapParams calldata params
    ) external override lock returns (int256 amount0, int256 amount1) {
        bytes32 poolId = getPoolId(key);
        Pool storage pool = pools[poolId];
        
        require(pool.sqrtPriceX96 != 0, "NOT_INITIALIZED");
        require(
            params.sqrtPriceLimitX96 >= TickMath.MIN_SQRT_RATIO &&
            params.sqrtPriceLimitX96 < TickMath.MAX_SQRT_RATIO,
            "PRICE_LIMIT_BOUNDS"
        );
        
        // Validate price limit direction
        if (params.zeroForOne) {
            require(params.sqrtPriceLimitX96 < pool.sqrtPriceX96, "PRICE_LIMIT_INVALID");
        } else {
            require(params.sqrtPriceLimitX96 > pool.sqrtPriceX96, "PRICE_LIMIT_INVALID");
        }
        
        // Call beforeSwap hook if present
        if (key.hooks != address(0)) {
            bytes4 selector = IHooks(key.hooks).beforeSwap(msg.sender, key, params);
            require(selector == IHooks.beforeSwap.selector, "HOOK_FAILED");
        }
        
        // Execute swap
        SwapState memory state = SwapState({
            amountSpecifiedRemaining: params.amountSpecified,
            amountCalculated: 0,
            sqrtPriceX96: pool.sqrtPriceX96,
            tick: pool.tick,
            liquidity: pool.liquidity
        });
        
        // Swap loop - process until amount filled or price limit reached
        while (state.amountSpecifiedRemaining != 0 && state.sqrtPriceX96 != params.sqrtPriceLimitX96) {
            StepComputations memory step;
            
            step.sqrtPriceStartX96 = state.sqrtPriceX96;
            
            // Get next initialized tick
            (step.tickNext, step.initialized) = nextInitializedTickWithinOneWord(
                poolId,
                state.tick,
                key.tickSpacing,
                params.zeroForOne
            );
            
            // Ensure tick is within bounds
            if (step.tickNext < TickMath.MIN_TICK) {
                step.tickNext = TickMath.MIN_TICK;
            } else if (step.tickNext > TickMath.MAX_TICK) {
                step.tickNext = TickMath.MAX_TICK;
            }
            
            // Get sqrt price at next tick
            step.sqrtPriceNextX96 = TickMath.getSqrtRatioAtTick(step.tickNext);
            
            // Compute swap to next price
            (state.sqrtPriceX96, step.amountIn, step.amountOut) = computeSwapStep(
                state.sqrtPriceX96,
                (params.zeroForOne ? step.sqrtPriceNextX96 < params.sqrtPriceLimitX96 : step.sqrtPriceNextX96 > params.sqrtPriceLimitX96)
                    ? params.sqrtPriceLimitX96
                    : step.sqrtPriceNextX96,
                state.liquidity,
                state.amountSpecifiedRemaining,
                key.fee
            );
            
            state.amountSpecifiedRemaining -= int256(step.amountIn);
            state.amountCalculated += int256(step.amountOut);
            
            // Update global fee growth
            if (state.liquidity > 0) {
                uint256 feeAmount = (step.amountIn * key.fee) / 1000000;
                if (params.zeroForOne) {
                    pool.feeGrowthGlobal0X128 += (feeAmount << 128) / state.liquidity;
                } else {
                    pool.feeGrowthGlobal1X128 += (feeAmount << 128) / state.liquidity;
                }
            }
            
            // Cross tick if price reached next tick
            if (state.sqrtPriceX96 == step.sqrtPriceNextX96) {
                if (step.initialized) {
                    int128 liquidityNet = ticks[poolId][step.tickNext].liquidityNet;
                    if (params.zeroForOne) liquidityNet = -liquidityNet;
                    state.liquidity = liquidityNet < 0
                        ? state.liquidity - uint128(-liquidityNet)
                        : state.liquidity + uint128(liquidityNet);
                }
                state.tick = params.zeroForOne ? step.tickNext - 1 : step.tickNext;
            } else if (state.sqrtPriceX96 != step.sqrtPriceStartX96) {
                // Recompute tick
                state.tick = TickMath.getTickAtSqrtRatio(state.sqrtPriceX96);
            }
        }
        
        // Update pool state
        pool.sqrtPriceX96 = state.sqrtPriceX96;
        pool.tick = state.tick;
        pool.liquidity = state.liquidity;
        
        // Calculate amounts
        if (params.zeroForOne) {
            amount0 = params.amountSpecified - state.amountSpecifiedRemaining;
            amount1 = -state.amountCalculated;
        } else {
            amount0 = -state.amountCalculated;
            amount1 = params.amountSpecified - state.amountSpecifiedRemaining;
        }
        
        // Call afterSwap hook if present
        if (key.hooks != address(0)) {
            bytes4 selector = IHooks(key.hooks).afterSwap(msg.sender, key, params, amount0, amount1);
            require(selector == IHooks.afterSwap.selector, "HOOK_FAILED");
        }
        
        emit Swap(poolId, msg.sender, amount0, amount1, state.sqrtPriceX96, state.liquidity, state.tick);
    }
    
    /**
     * @notice Modify liquidity position
     * @param key The pool key
     * @param params The position modification parameters
     * @return amount0 The delta of token0
     * @return amount1 The delta of token1
     */
    function modifyPosition(
        PoolKey calldata key,
        ModifyPositionParams calldata params
    ) external override lock returns (int256 amount0, int256 amount1) {
        bytes32 poolId = getPoolId(key);
        Pool storage pool = pools[poolId];
        
        require(pool.sqrtPriceX96 != 0, "NOT_INITIALIZED");
        require(params.tickLower < params.tickUpper, "TICK_ORDER");
        require(params.tickLower >= TickMath.MIN_TICK, "TICK_LOWER_BOUND");
        require(params.tickUpper <= TickMath.MAX_TICK, "TICK_UPPER_BOUND");
        
        // Call beforeModifyPosition hook if present
        if (key.hooks != address(0)) {
            bytes4 selector = IHooks(key.hooks).beforeModifyPosition(msg.sender, key, params);
            require(selector == IHooks.beforeModifyPosition.selector, "HOOK_FAILED");
        }
        
        // Update position
        Position storage position = positions[poolId][msg.sender][params.tickLower][params.tickUpper];
        
        // Update ticks
        if (params.liquidityDelta != 0) {
            updateTick(poolId, params.tickLower, params.liquidityDelta, false);
            updateTick(poolId, params.tickUpper, params.liquidityDelta, true);
        }
        
        // Update position liquidity
        uint128 liquidityBefore = position.liquidity;
        uint128 liquidityAfter;
        
        if (params.liquidityDelta < 0) {
            liquidityAfter = liquidityBefore - uint128(-params.liquidityDelta);
        } else {
            liquidityAfter = liquidityBefore + uint128(params.liquidityDelta);
        }
        
        position.liquidity = liquidityAfter;
        
        // Update pool liquidity if position is in range
        if (pool.tick >= params.tickLower && pool.tick < params.tickUpper) {
            if (params.liquidityDelta < 0) {
                pool.liquidity -= uint128(-params.liquidityDelta);
            } else {
                pool.liquidity += uint128(params.liquidityDelta);
            }
        }
        
        // Calculate token amounts
        uint160 sqrtPriceLowerX96 = TickMath.getSqrtRatioAtTick(params.tickLower);
        uint160 sqrtPriceUpperX96 = TickMath.getSqrtRatioAtTick(params.tickUpper);
        
        if (pool.tick < params.tickLower) {
            // Position is above current price (only token0)
            amount0 = int256(
                SqrtPriceMath.getAmount0ForLiquidity(
                    sqrtPriceLowerX96,
                    sqrtPriceUpperX96,
                    uint128(params.liquidityDelta < 0 ? -params.liquidityDelta : params.liquidityDelta)
                )
            );
            if (params.liquidityDelta < 0) amount0 = -amount0;
        } else if (pool.tick >= params.tickUpper) {
            // Position is below current price (only token1)
            amount1 = int256(
                SqrtPriceMath.getAmount1ForLiquidity(
                    sqrtPriceLowerX96,
                    sqrtPriceUpperX96,
                    uint128(params.liquidityDelta < 0 ? -params.liquidityDelta : params.liquidityDelta)
                )
            );
            if (params.liquidityDelta < 0) amount1 = -amount1;
        } else {
            // Position is in range (both tokens)
            amount0 = int256(
                SqrtPriceMath.getAmount0ForLiquidity(
                    pool.sqrtPriceX96,
                    sqrtPriceUpperX96,
                    uint128(params.liquidityDelta < 0 ? -params.liquidityDelta : params.liquidityDelta)
                )
            );
            amount1 = int256(
                SqrtPriceMath.getAmount1ForLiquidity(
                    sqrtPriceLowerX96,
                    pool.sqrtPriceX96,
                    uint128(params.liquidityDelta < 0 ? -params.liquidityDelta : params.liquidityDelta)
                )
            );
            
            if (params.liquidityDelta < 0) {
                amount0 = -amount0;
                amount1 = -amount1;
            }
        }
        
        // Update fee tracking
        position.feeGrowthInside0LastX128 = getFeeGrowthInside(poolId, params.tickLower, params.tickUpper, pool.tick, pool.feeGrowthGlobal0X128, 0);
        position.feeGrowthInside1LastX128 = getFeeGrowthInside(poolId, params.tickLower, params.tickUpper, pool.tick, pool.feeGrowthGlobal1X128, 1);
        
        // Call afterModifyPosition hook if present
        if (key.hooks != address(0)) {
            bytes4 selector = IHooks(key.hooks).afterModifyPosition(msg.sender, key, params, amount0, amount1);
            require(selector == IHooks.afterModifyPosition.selector, "HOOK_FAILED");
        }
        
        emit ModifyPosition(poolId, msg.sender, params.tickLower, params.tickUpper, params.liquidityDelta);
    }
    
    /**
     * @notice Collect accumulated fees from a position
     * @param key The pool key
     * @param tickLower The lower tick boundary
     * @param tickUpper The upper tick boundary
     * @return amount0 The amount of token0 fees collected
     * @return amount1 The amount of token1 fees collected
     */
    function collect(
        PoolKey calldata key,
        int24 tickLower,
        int24 tickUpper
    ) external override lock returns (uint256 amount0, uint256 amount1) {
        bytes32 poolId = getPoolId(key);
        Pool storage pool = pools[poolId];
        Position storage position = positions[poolId][msg.sender][tickLower][tickUpper];
        
        // Calculate fees owed
        uint256 feeGrowthInside0X128 = getFeeGrowthInside(poolId, tickLower, tickUpper, pool.tick, pool.feeGrowthGlobal0X128, 0);
        uint256 feeGrowthInside1X128 = getFeeGrowthInside(poolId, tickLower, tickUpper, pool.tick, pool.feeGrowthGlobal1X128, 1);
        
        amount0 = uint256(
            int256((feeGrowthInside0X128 - position.feeGrowthInside0LastX128) * position.liquidity >> 128)
        ) + position.tokensOwed0;
        
        amount1 = uint256(
            int256((feeGrowthInside1X128 - position.feeGrowthInside1LastX128) * position.liquidity >> 128)
        ) + position.tokensOwed1;
        
        // Update position
        position.feeGrowthInside0LastX128 = feeGrowthInside0X128;
        position.feeGrowthInside1LastX128 = feeGrowthInside1X128;
        position.tokensOwed0 = 0;
        position.tokensOwed1 = 0;
        
        emit Collect(poolId, msg.sender, tickLower, tickUpper, amount0, amount1);
    }
    
    /**
     * @notice Get pool state
     * @param key The pool key
     * @return pool The pool state
     */
    function getPool(PoolKey calldata key) external view override returns (Pool memory pool) {
        return pools[getPoolId(key)];
    }
    
    /**
     * @notice Get position state
     * @param key The pool key
     * @param owner The position owner
     * @param tickLower The lower tick boundary
     * @param tickUpper The upper tick boundary
     * @return position The position state
     */
    function getPosition(
        PoolKey calldata key,
        address owner,
        int24 tickLower,
        int24 tickUpper
    ) external view override returns (Position memory position) {
        bytes32 poolId = getPoolId(key);
        return positions[poolId][owner][tickLower][tickUpper];
    }
    
    /**
     * @notice Calculate pool ID using quantum-resistant BLAKE3
     * @param key The pool key
     * @return poolId The unique pool identifier
     */
    function getPoolId(PoolKey memory key) public view override returns (bytes32 poolId) {
        bytes memory data = abi.encode(key.token0, key.token1, key.fee, key.tickSpacing, key.hooks);
        
        // Call BLAKE3 precompile (0x0c)
        (bool success, bytes memory result) = BLAKE3_PRECOMPILE.staticcall(data);
        require(success, "BLAKE3_FAILED");
        
        poolId = bytes32(result);
    }
    
    // ============ Internal Functions ============
    
    struct SwapState {
        int256 amountSpecifiedRemaining;
        int256 amountCalculated;
        uint160 sqrtPriceX96;
        int24 tick;
        uint128 liquidity;
    }
    
    struct StepComputations {
        uint160 sqrtPriceStartX96;
        int24 tickNext;
        bool initialized;
        uint160 sqrtPriceNextX96;
        uint256 amountIn;
        uint256 amountOut;
    }
    
    function computeSwapStep(
        uint160 sqrtPriceCurrentX96,
        uint160 sqrtPriceTargetX96,
        uint128 liquidity,
        int256 amountRemaining,
        uint24 fee
    ) internal pure returns (uint160 sqrtPriceNextX96, uint256 amountIn, uint256 amountOut) {
        bool zeroForOne = sqrtPriceCurrentX96 >= sqrtPriceTargetX96;
        
        amountIn = uint256(amountRemaining < 0 ? -amountRemaining : amountRemaining);
        
        // Calculate new price after swap
        sqrtPriceNextX96 = SqrtPriceMath.getNextSqrtPriceFromAmount(
            sqrtPriceCurrentX96,
            liquidity,
            amountIn,
            zeroForOne
        );
        
        // Cap at target price
        if (zeroForOne) {
            if (sqrtPriceNextX96 < sqrtPriceTargetX96) sqrtPriceNextX96 = sqrtPriceTargetX96;
        } else {
            if (sqrtPriceNextX96 > sqrtPriceTargetX96) sqrtPriceNextX96 = sqrtPriceTargetX96;
        }
        
        // Calculate amounts
        if (zeroForOne) {
            amountIn = SqrtPriceMath.getAmount0Delta(sqrtPriceCurrentX96, sqrtPriceNextX96, liquidity);
            amountOut = SqrtPriceMath.getAmount1Delta(sqrtPriceCurrentX96, sqrtPriceNextX96, liquidity);
        } else {
            amountIn = SqrtPriceMath.getAmount1Delta(sqrtPriceCurrentX96, sqrtPriceNextX96, liquidity);
            amountOut = SqrtPriceMath.getAmount0Delta(sqrtPriceCurrentX96, sqrtPriceNextX96, liquidity);
        }
        
        // Apply fee
        amountOut = (amountOut * (1000000 - fee)) / 1000000;
    }
    
    function updateTick(
        bytes32 poolId,
        int24 tick,
        int128 liquidityDelta,
        bool upper
    ) internal {
        TickInfo storage tickInfo = ticks[poolId][tick];
        
        uint128 liquidityGrossBefore = tickInfo.liquidityGross;
        uint128 liquidityGrossAfter = liquidityDelta < 0
            ? liquidityGrossBefore - uint128(-liquidityDelta)
            : liquidityGrossBefore + uint128(liquidityDelta);
        
        tickInfo.liquidityGross = liquidityGrossAfter;
        
        // Update liquidity net
        tickInfo.liquidityNet = upper
            ? tickInfo.liquidityNet - liquidityDelta
            : tickInfo.liquidityNet + liquidityDelta;
        
        // Mark tick as initialized if it wasn't before
        if (!tickInfo.initialized && liquidityGrossAfter > 0) {
            tickInfo.initialized = true;
        }
    }
    
    function nextInitializedTickWithinOneWord(
        bytes32 poolId,
        int24 tick,
        int24 tickSpacing,
        bool lte
    ) internal view returns (int24 next, bool initialized) {
        // Compress tick
        int24 compressed = tick / tickSpacing;
        if (tick < 0 && tick % tickSpacing != 0) compressed--;
        
        if (lte) {
            // Search left
            for (int24 i = 0; i < 256; i++) {
                int24 checkTick = (compressed - i) * tickSpacing;
                if (checkTick < TickMath.MIN_TICK) break;
                
                if (ticks[poolId][checkTick].initialized) {
                    return (checkTick, true);
                }
            }
            return (TickMath.MIN_TICK, false);
        } else {
            // Search right
            for (int24 i = 1; i <= 256; i++) {
                int24 checkTick = (compressed + i) * tickSpacing;
                if (checkTick > TickMath.MAX_TICK) break;
                
                if (ticks[poolId][checkTick].initialized) {
                    return (checkTick, true);
                }
            }
            return (TickMath.MAX_TICK, false);
        }
    }
    
    function getFeeGrowthInside(
        bytes32 poolId,
        int24 tickLower,
        int24 tickUpper,
        int24 tickCurrent,
        uint256 feeGrowthGlobalX128,
        uint8 tokenIndex
    ) internal view returns (uint256 feeGrowthInsideX128) {
        TickInfo storage lower = ticks[poolId][tickLower];
        TickInfo storage upper = ticks[poolId][tickUpper];
        
        uint256 feeGrowthBelow;
        uint256 feeGrowthAbove;
        
        // Calculate fee growth below
        if (tickCurrent >= tickLower) {
            feeGrowthBelow = tokenIndex == 0 ? lower.feeGrowthOutside0X128 : lower.feeGrowthOutside1X128;
        } else {
            feeGrowthBelow = feeGrowthGlobalX128 - (tokenIndex == 0 ? lower.feeGrowthOutside0X128 : lower.feeGrowthOutside1X128);
        }
        
        // Calculate fee growth above
        if (tickCurrent < tickUpper) {
            feeGrowthAbove = tokenIndex == 0 ? upper.feeGrowthOutside0X128 : upper.feeGrowthOutside1X128;
        } else {
            feeGrowthAbove = feeGrowthGlobalX128 - (tokenIndex == 0 ? upper.feeGrowthOutside0X128 : upper.feeGrowthOutside1X128);
        }
        
        feeGrowthInsideX128 = feeGrowthGlobalX128 - feeGrowthBelow - feeGrowthAbove;
    }
}
