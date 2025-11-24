// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title PoolTypes
 * @notice Shared types for QRDX AMM
 */
library PoolTypes {
    struct PoolKey {
        address token0;
        address token1;
        uint24 fee;
        int24 tickSpacing;
        address hooks;
    }
    
    struct Pool {
        uint160 sqrtPriceX96;
        int24 tick;
        uint128 liquidity;
        uint256 feeGrowthGlobal0X128;
        uint256 feeGrowthGlobal1X128;
    }
    
    struct Position {
        uint128 liquidity;
        uint256 feeGrowthInside0LastX128;
        uint256 feeGrowthInside1LastX128;
        uint256 tokensOwed0;
        uint256 tokensOwed1;
    }
    
    struct SwapParams {
        bool zeroForOne;
        int256 amountSpecified;
        uint160 sqrtPriceLimitX96;
    }
    
    struct ModifyPositionParams {
        int24 tickLower;
        int24 tickUpper;
        int128 liquidityDelta;
    }
}
