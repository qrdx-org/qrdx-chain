// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./PoolTypes.sol";

/**
 * @title IHooks
 * @notice Interface for pool hooks in the QRDX AMM
 * 
 * Hooks allow custom logic to be executed at key points in the pool lifecycle:
 * - Before/after pool initialization
 * - Before/after swaps
 * - Before/after liquidity modifications
 * 
 * Hook contracts can customize behavior without modifying the core pool logic.
 */
interface IHooks {
    /**
     * @notice Called before pool initialization
     * @param sender Address calling initialize
     * @param key Pool key
     * @param sqrtPriceX96 Initial price
     * @return bytes4 Function selector if successful
     */
    function beforeInitialize(
        address sender,
        PoolTypes.PoolKey calldata key,
        uint160 sqrtPriceX96
    ) external returns (bytes4);
    
    /**
     * @notice Called after pool initialization
     * @param sender Address calling initialize
     * @param key Pool key
     * @param sqrtPriceX96 Initial price
     * @param tick Initial tick
     * @return bytes4 Function selector if successful
     */
    function afterInitialize(
        address sender,
        PoolTypes.PoolKey calldata key,
        uint160 sqrtPriceX96,
        int24 tick
    ) external returns (bytes4);
    
    /**
     * @notice Called before a swap
     * @param sender Address calling swap
     * @param key Pool key
     * @param params Swap parameters
     * @return bytes4 Function selector if successful
     */
    function beforeSwap(
        address sender,
        PoolTypes.PoolKey calldata key,
        PoolTypes.SwapParams calldata params
    ) external returns (bytes4);
    
    /**
     * @notice Called after a swap
     * @param sender Address calling swap
     * @param key Pool key
     * @param params Swap parameters
     * @param delta0 Token0 delta
     * @param delta1 Token1 delta
     * @return bytes4 Function selector if successful
     */
    function afterSwap(
        address sender,
        PoolTypes.PoolKey calldata key,
        PoolTypes.SwapParams calldata params,
        int256 delta0,
        int256 delta1
    ) external returns (bytes4);
    
    /**
     * @notice Called before modifying position
     * @param sender Address calling modify
     * @param key Pool key
     * @param params Modify parameters
     * @return bytes4 Function selector if successful
     */
    function beforeModifyPosition(
        address sender,
        PoolTypes.PoolKey calldata key,
        PoolTypes.ModifyPositionParams calldata params
    ) external returns (bytes4);
    
    /**
     * @notice Called after modifying position
     * @param sender Address calling modify
     * @param key Pool key
     * @param params Modify parameters
     * @param delta0 Token0 delta
     * @param delta1 Token1 delta
     * @return bytes4 Function selector if successful
     */
    function afterModifyPosition(
        address sender,
        PoolTypes.PoolKey calldata key,
        PoolTypes.ModifyPositionParams calldata params,
        int256 delta0,
        int256 delta1
    ) external returns (bytes4);
}
