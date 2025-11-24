// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SqrtPriceMath
 * @notice Mathematical functions for sqrt price and liquidity calculations
 * 
 * Handles price impact calculations and liquidity math for concentrated liquidity pools.
 */
library SqrtPriceMath {
    /**
     * @notice Gets the next sqrt price given an amount of token0 or token1
     * @param sqrtPriceX96 The starting sqrt price
     * @param liquidity The amount of usable liquidity
     * @param amount The amount of token0 or token1 being swapped in
     * @param zeroForOne Whether the swap is token0 for token1
     * @return sqrtPriceNextX96 The next sqrt price
     */
    function getNextSqrtPriceFromAmount(
        uint160 sqrtPriceX96,
        uint128 liquidity,
        uint256 amount,
        bool zeroForOne
    ) internal pure returns (uint160 sqrtPriceNextX96) {
        require(sqrtPriceX96 > 0, "P");
        require(liquidity > 0, "L");
        
        if (zeroForOne) {
            // Buying token1, price moves down
            uint256 product = amount * sqrtPriceX96;
            if (product / amount == sqrtPriceX96) {
                uint256 denominator = uint256(liquidity) * (1 << 96) + product;
                if (denominator > product) {
                    return uint160((uint256(liquidity) * sqrtPriceX96 * (1 << 96)) / denominator);
                }
            }
            
            return uint160((uint256(liquidity) * (1 << 96)) / (uint256(liquidity) + mulDiv(amount, sqrtPriceX96, 1 << 96)));
        } else {
            // Buying token0, price moves up
            uint256 quotient = mulDiv(amount, 1 << 96, liquidity);
            return uint160(sqrtPriceX96 + quotient);
        }
    }
    
    /**
     * @notice Gets the amount of token0 for a liquidity change
     * @param sqrtPriceAX96 The lower sqrt price
     * @param sqrtPriceBX96 The upper sqrt price
     * @param liquidity The liquidity amount
     * @return amount0 The amount of token0
     */
    function getAmount0ForLiquidity(
        uint160 sqrtPriceAX96,
        uint160 sqrtPriceBX96,
        uint128 liquidity
    ) internal pure returns (uint256 amount0) {
        if (sqrtPriceAX96 > sqrtPriceBX96) (sqrtPriceAX96, sqrtPriceBX96) = (sqrtPriceBX96, sqrtPriceAX96);
        
        return mulDiv(
            uint256(liquidity) * (1 << 96),
            sqrtPriceBX96 - sqrtPriceAX96,
            sqrtPriceBX96
        ) / sqrtPriceAX96;
    }
    
    /**
     * @notice Gets the amount of token1 for a liquidity change
     * @param sqrtPriceAX96 The lower sqrt price
     * @param sqrtPriceBX96 The upper sqrt price
     * @param liquidity The liquidity amount
     * @return amount1 The amount of token1
     */
    function getAmount1ForLiquidity(
        uint160 sqrtPriceAX96,
        uint160 sqrtPriceBX96,
        uint128 liquidity
    ) internal pure returns (uint256 amount1) {
        if (sqrtPriceAX96 > sqrtPriceBX96) (sqrtPriceAX96, sqrtPriceBX96) = (sqrtPriceBX96, sqrtPriceAX96);
        
        return mulDiv(liquidity, sqrtPriceBX96 - sqrtPriceAX96, 1 << 96);
    }
    
    /**
     * @notice Calculates amount0 delta for a swap
     * @param sqrtPriceAX96 The starting sqrt price
     * @param sqrtPriceBX96 The ending sqrt price
     * @param liquidity The liquidity amount
     * @return amount0 The amount of token0 delta
     */
    function getAmount0Delta(
        uint160 sqrtPriceAX96,
        uint160 sqrtPriceBX96,
        uint128 liquidity
    ) internal pure returns (uint256 amount0) {
        if (sqrtPriceAX96 > sqrtPriceBX96) (sqrtPriceAX96, sqrtPriceBX96) = (sqrtPriceBX96, sqrtPriceAX96);
        
        require(sqrtPriceAX96 > 0, "PA");
        
        uint256 numerator1 = uint256(liquidity) * (1 << 96);
        uint256 numerator2 = sqrtPriceBX96 - sqrtPriceAX96;
        
        return mulDiv(numerator1, numerator2, sqrtPriceBX96) / sqrtPriceAX96;
    }
    
    /**
     * @notice Calculates amount1 delta for a swap
     * @param sqrtPriceAX96 The starting sqrt price
     * @param sqrtPriceBX96 The ending sqrt price
     * @param liquidity The liquidity amount
     * @return amount1 The amount of token1 delta
     */
    function getAmount1Delta(
        uint160 sqrtPriceAX96,
        uint160 sqrtPriceBX96,
        uint128 liquidity
    ) internal pure returns (uint256 amount1) {
        if (sqrtPriceAX96 > sqrtPriceBX96) (sqrtPriceAX96, sqrtPriceBX96) = (sqrtPriceBX96, sqrtPriceAX96);
        
        return mulDiv(liquidity, sqrtPriceBX96 - sqrtPriceAX96, 1 << 96);
    }
    
    /**
     * @notice Calculates ceil(a×b÷denominator)
     * @param a The multiplicand
     * @param b The multiplier
     * @param denominator The divisor
     * @return result The 256-bit result
     */
    function mulDiv(
        uint256 a,
        uint256 b,
        uint256 denominator
    ) internal pure returns (uint256 result) {
        uint256 prod0;
        uint256 prod1;
        assembly {
            let mm := mulmod(a, b, not(0))
            prod0 := mul(a, b)
            prod1 := sub(sub(mm, prod0), lt(mm, prod0))
        }
        
        if (prod1 == 0) {
            require(denominator > 0, "D");
            assembly {
                result := div(prod0, denominator)
            }
            return result;
        }
        
        require(denominator > prod1, "OV");
        
        uint256 remainder;
        assembly {
            remainder := mulmod(a, b, denominator)
        }
        assembly {
            prod1 := sub(prod1, gt(remainder, prod0))
            prod0 := sub(prod0, remainder)
        }
        
        uint256 twos = denominator & (~denominator + 1);
        assembly {
            denominator := div(denominator, twos)
        }
        
        assembly {
            prod0 := div(prod0, twos)
        }
        assembly {
            twos := add(div(sub(0, twos), twos), 1)
        }
        prod0 |= prod1 * twos;
        
        uint256 inv = (3 * denominator) ^ 2;
        inv *= 2 - denominator * inv;
        inv *= 2 - denominator * inv;
        inv *= 2 - denominator * inv;
        inv *= 2 - denominator * inv;
        inv *= 2 - denominator * inv;
        inv *= 2 - denominator * inv;
        
        result = prod0 * inv;
        return result;
    }
}
