// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IHooks.sol";
import "./IPoolManager.sol";

/**
 * @title LimitOrderHook
 * @notice Example hook implementing limit orders on concentrated liquidity positions
 * 
 * Demonstrates how hooks can add custom behavior without modifying core pool logic.
 * Users can place limit orders that automatically fill when price crosses their tick.
 */
contract LimitOrderHook is IHooks {
    IPoolManager public immutable poolManager;
    
    struct LimitOrder {
        address owner;
        int24 tick;
        uint128 amount;
        bool zeroForOne;
        bool filled;
    }
    
    /// @notice All limit orders by pool ID and order ID
    mapping(bytes32 => mapping(uint256 => LimitOrder)) public orders;
    
    /// @notice Next order ID for each pool
    mapping(bytes32 => uint256) public nextOrderId;
    
    /// @notice Orders by tick for efficient lookup
    mapping(bytes32 => mapping(int24 => uint256[])) public ordersByTick;
    
    event OrderPlaced(bytes32 indexed poolId, uint256 indexed orderId, address indexed owner, int24 tick, uint128 amount, bool zeroForOne);
    event OrderFilled(bytes32 indexed poolId, uint256 indexed orderId, uint128 amountFilled);
    event OrderCancelled(bytes32 indexed poolId, uint256 indexed orderId);
    
    constructor(address _poolManager) {
        poolManager = IPoolManager(_poolManager);
    }
    
    /**
     * @notice Place a limit order
     * @param poolKey The pool key
     * @param tick The tick at which to fill the order
     * @param amount The amount to fill
     * @param zeroForOne Whether selling token0 for token1
     * @return orderId The unique order identifier
     */
    function placeOrder(
        IPoolManager.PoolKey calldata poolKey,
        int24 tick,
        uint128 amount,
        bool zeroForOne
    ) external returns (uint256 orderId) {
        bytes32 poolId = poolManager.getPoolId(poolKey);
        orderId = nextOrderId[poolId]++;
        
        orders[poolId][orderId] = LimitOrder({
            owner: msg.sender,
            tick: tick,
            amount: amount,
            zeroForOne: zeroForOne,
            filled: false
        });
        
        ordersByTick[poolId][tick].push(orderId);
        
        emit OrderPlaced(poolId, orderId, msg.sender, tick, amount, zeroForOne);
    }
    
    /**
     * @notice Cancel a limit order
     * @param poolKey The pool key
     * @param orderId The order ID to cancel
     */
    function cancelOrder(
        IPoolManager.PoolKey calldata poolKey,
        uint256 orderId
    ) external {
        bytes32 poolId = poolManager.getPoolId(poolKey);
        LimitOrder storage order = orders[poolId][orderId];
        
        require(order.owner == msg.sender, "NOT_OWNER");
        require(!order.filled, "ALREADY_FILLED");
        
        order.filled = true; // Mark as filled to prevent execution
        
        emit OrderCancelled(poolId, orderId);
    }
    
    // ============ Hook Implementations ============
    
    function beforeInitialize(
        address,
        IPoolManager.PoolKey calldata,
        uint160
    ) external pure override returns (bytes4) {
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
        IPoolManager.PoolKey calldata,
        IPoolManager.SwapParams calldata
    ) external pure override returns (bytes4) {
        return IHooks.beforeSwap.selector;
    }
    
    function afterSwap(
        address sender,
        IPoolManager.PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        int256,
        int256
    ) external override returns (bytes4) {
        // Check if any limit orders should be filled
        bytes32 poolId = poolManager.getPoolId(key);
        IPoolManager.Pool memory pool = poolManager.getPool(key);
        
        // Process orders at crossed ticks
        int24 tickToCheck = pool.tick;
        uint256[] storage orderIds = ordersByTick[poolId][tickToCheck];
        
        for (uint256 i = 0; i < orderIds.length; i++) {
            uint256 orderId = orderIds[i];
            LimitOrder storage order = orders[poolId][orderId];
            
            if (!order.filled && order.zeroForOne == params.zeroForOne) {
                // Fill the order
                order.filled = true;
                emit OrderFilled(poolId, orderId, order.amount);
                
                // In a production implementation, would execute the fill here
                // For example, by calling back into the pool manager to swap
            }
        }
        
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
}
