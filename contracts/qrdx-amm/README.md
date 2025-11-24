# QRDX AMM Protocol

## Overview

The QRDX AMM (Automated Market Maker) is a quantum-resistant decentralized exchange protocol built on concentrated liquidity principles. Inspired by Uniswap v4, it implements a singleton pattern where a single contract manages all pools, with an extensible hooks system for custom behavior.

## Architecture

### Core Components

1. **PoolManager.sol** - Singleton contract managing all AMM pools
2. **IPoolManager.sol** - Pool manager interface defining core functionality
3. **IHooks.sol** - Hooks interface for extensibility
4. **TickMath.sol** - Mathematical library for tick and sqrt price conversions
5. **SqrtPriceMath.sol** - Price impact and liquidity calculations

### Design Patterns

- **Singleton Pattern**: One contract manages all pools for gas efficiency
- **Concentrated Liquidity**: Capital-efficient tick-based pricing (Uniswap v3 style)
- **Hooks System**: Extensible architecture allowing custom behavior without forks
- **Flash Accounting**: Efficient token tracking and settlement
- **Quantum-Resistant**: Uses BLAKE3 (precompile 0x0c) for pool identification

## Key Features

### 1. Concentrated Liquidity

Liquidity providers can concentrate capital within specific price ranges (ticks) for improved capital efficiency:

```solidity
// Add liquidity to price range
ModifyPositionParams memory params = ModifyPositionParams({
    tickLower: -1000,      // Lower price bound
    tickUpper: 1000,       // Upper price bound
    liquidityDelta: 1e18   // Amount to add
});

poolManager.modifyPosition(poolKey, params);
```

### 2. Multiple Fee Tiers

Pools can have different fee levels to accommodate varying market conditions:

- 0.05% (500) - Stable pairs
- 0.3% (3000) - Standard pairs
- 1% (10000) - Exotic/volatile pairs

### 3. Extensible Hooks

Hooks allow custom logic at pool lifecycle points without modifying core contracts:

- `beforeInitialize` / `afterInitialize` - Pool creation
- `beforeSwap` / `afterSwap` - Swap execution
- `beforeModifyPosition` / `afterModifyPosition` - Liquidity changes

Example use cases:
- Limit orders
- Dynamic fees based on volatility
- Access control (whitelists)
- MEV protection
- Custom oracle updates

## Technical Specifications

### Price Representation

Prices are stored as Q64.96 fixed-point numbers (sqrt price format):

```
sqrtPriceX96 = sqrt(price) * 2^96
price = token1 / token0
```

### Tick System

Ticks represent discrete price points:

```
price = 1.0001^tick
tick_range = [-887272, 887272]
```

### Pool Identification

Pool IDs are generated using quantum-resistant BLAKE3 hashing:

```solidity
bytes32 poolId = BLAKE3(
    token0 || token1 || fee || tickSpacing || hooks
);
```

## Core Functions

### Initialize Pool

```solidity
function initialize(
    PoolKey calldata key,
    uint160 sqrtPriceX96
) external returns (bytes32 poolId);
```

Creates a new pool with specified parameters and initial price.

**Parameters:**
- `key` - Pool identification (token0, token1, fee, tickSpacing, hooks)
- `sqrtPriceX96` - Initial sqrt price (Q64.96 format)

**Returns:**
- `poolId` - Unique pool identifier (BLAKE3 hash)

**Gas Cost:** ~200,000 gas

### Swap

```solidity
function swap(
    PoolKey calldata key,
    SwapParams calldata params
) external returns (int256 amount0, int256 amount1);
```

Execute a token swap with price limit protection.

**Parameters:**
- `key` - Pool identification
- `params.zeroForOne` - Swap direction (true = token0 → token1)
- `params.amountSpecified` - Input amount (positive) or output amount (negative)
- `params.sqrtPriceLimitX96` - Maximum price movement allowed

**Returns:**
- `amount0` - Token0 delta (negative = out, positive = in)
- `amount1` - Token1 delta (negative = out, positive = in)

**Gas Cost:** ~100,000-150,000 gas (varies with price range crossings)

### Modify Position

```solidity
function modifyPosition(
    PoolKey calldata key,
    ModifyPositionParams calldata params
) external returns (int256 amount0, int256 amount1);
```

Add or remove liquidity from a position.

**Parameters:**
- `key` - Pool identification
- `params.tickLower` - Lower price bound
- `params.tickUpper` - Upper price bound
- `params.liquidityDelta` - Liquidity change (positive = add, negative = remove)

**Returns:**
- `amount0` - Token0 required/returned
- `amount1` - Token1 required/returned

**Gas Cost:** ~150,000-200,000 gas (varies with tick initialization)

### Collect Fees

```solidity
function collect(
    PoolKey calldata key,
    int24 tickLower,
    int24 tickUpper
) external returns (uint256 amount0, uint256 amount1);
```

Collect accumulated trading fees from a position.

**Parameters:**
- `key` - Pool identification
- `tickLower` - Lower tick of position
- `tickUpper` - Upper tick of position

**Returns:**
- `amount0` - Token0 fees collected
- `amount1` - Token1 fees collected

**Gas Cost:** ~80,000 gas

## Example Hooks

### 1. Limit Order Hook

Implements limit orders on top of concentrated liquidity:

```solidity
// Place limit order
uint256 orderId = limitOrderHook.placeOrder(
    poolKey,
    targetTick,    // Price to fill at
    amount,        // Amount to fill
    zeroForOne     // Direction
);

// Cancel order
limitOrderHook.cancelOrder(poolKey, orderId);
```

**Use Cases:**
- Automated limit orders
- Stop-loss orders
- Take-profit orders
- TWAP execution

### 2. Dynamic Fee Hook

Adjusts fees based on market volatility:

```solidity
// Get current dynamic fee
uint24 currentFee = dynamicFeeHook.getCurrentFee(poolKey);

// Fees automatically adjust based on:
// - Recent price volatility
// - Trading volume
// - Time of day
```

**Benefits:**
- LPs earn more during volatile periods
- Reduces impermanent loss impact
- Automatic fee optimization

## Usage Examples

### Creating a Pool

```solidity
// Define pool parameters
IPoolManager.PoolKey memory poolKey = IPoolManager.PoolKey({
    token0: address(tokenA),           // Lower address
    token1: address(tokenB),           // Higher address
    fee: 3000,                         // 0.3% fee
    tickSpacing: 60,                   // Tick granularity
    hooks: address(0)                  // No hooks
});

// Initialize with price = 1.0 (sqrtPrice = 2^96)
uint160 sqrtPriceX96 = 79228162514264337593543950336;
bytes32 poolId = poolManager.initialize(poolKey, sqrtPriceX96);
```

### Adding Liquidity

```solidity
// Approve tokens
tokenA.approve(address(poolManager), amountA);
tokenB.approve(address(poolManager), amountB);

// Add liquidity to current price range
IPoolManager.ModifyPositionParams memory params = IPoolManager.ModifyPositionParams({
    tickLower: -1000,              // ~0.9 price
    tickUpper: 1000,               // ~1.1 price
    liquidityDelta: int128(1e18)   // 1 ETH equivalent
});

(int256 amount0, int256 amount1) = poolManager.modifyPosition(poolKey, params);

// Transfer tokens to pool
// (In production, would use a router contract for this)
```

### Executing a Swap

```solidity
// Approve input token
tokenA.approve(address(poolManager), amountIn);

// Swap with 1% slippage protection
IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
    zeroForOne: true,                          // token0 → token1
    amountSpecified: int256(amountIn),        // Exact input
    sqrtPriceLimitX96: calculatePriceLimit()  // 1% slippage
});

(int256 amount0, int256 amount1) = poolManager.swap(poolKey, params);

// amount0 = input (positive)
// amount1 = output (negative)
```

### Removing Liquidity

```solidity
// Remove all liquidity from position
IPoolManager.ModifyPositionParams memory params = IPoolManager.ModifyPositionParams({
    tickLower: -1000,
    tickUpper: 1000,
    liquidityDelta: -int128(position.liquidity)  // Negative = remove
});

(int256 amount0, int256 amount1) = poolManager.modifyPosition(poolKey, params);

// Collect accrued fees
(uint256 fees0, uint256 fees1) = poolManager.collect(poolKey, -1000, 1000);
```

## Security Considerations

### 1. Price Manipulation

- Use large liquidity positions to resist manipulation
- Implement TWAP oracles for critical operations
- Consider using dynamic fees during volatile periods

### 2. Reentrancy

- All state-changing functions use reentrancy locks
- Follow checks-effects-interactions pattern
- Be cautious with hook implementations

### 3. Quantum Resistance

- Pool IDs use BLAKE3 (precompile 0x0c) for quantum resistance
- Compatible with qRC20 tokens using Dilithium signatures
- Future-proof against quantum attacks

### 4. Hook Safety

- Hooks can modify pool behavior significantly
- Always audit hook contracts before use
- Consider using hook whitelists for production

### 5. Liquidity Risks

- Positions can experience impermanent loss
- Concentrated liquidity increases risk in volatile markets
- Diversify across multiple price ranges

## Gas Optimization

### Tips for Lower Gas Costs

1. **Batch Operations**: Use multicall patterns to batch multiple operations
2. **Optimal Tick Spacing**: Wider tick spacing = fewer ticks crossed = lower gas
3. **Position Sizing**: Fewer, larger positions cost less than many small ones
4. **Hook Selection**: Pools without hooks consume less gas
5. **Price Range**: Positions near current price are cheapest to maintain

### Gas Benchmarks

| Operation | Gas Cost | Notes |
|-----------|----------|-------|
| Initialize Pool | ~200,000 | One-time cost |
| Swap (no tick cross) | ~100,000 | Optimal case |
| Swap (tick cross) | ~150,000 | Per tick crossed |
| Add Liquidity | ~150,000 | First position in tick |
| Add Liquidity | ~100,000 | Existing tick |
| Remove Liquidity | ~80,000 | Average |
| Collect Fees | ~80,000 | Average |

## Integration Guide

### For Traders

1. **Approve Tokens**: Grant allowance to PoolManager
2. **Calculate Price Limits**: Determine acceptable slippage
3. **Execute Swap**: Call `swap()` with parameters
4. **Handle Results**: Process returned token amounts

### For Liquidity Providers

1. **Choose Price Range**: Select ticks based on strategy
2. **Calculate Liquidity**: Determine position size
3. **Add Position**: Call `modifyPosition()` with positive delta
4. **Monitor Position**: Track fees and price movement
5. **Rebalance/Exit**: Adjust or remove position as needed

### For Hook Developers

1. **Implement IHooks**: Create contract implementing all hook functions
2. **Return Selectors**: Each hook must return its function selector
3. **Test Thoroughly**: Hooks can significantly affect pool behavior
4. **Gas Efficiency**: Hooks execute on every operation - optimize carefully
5. **Error Handling**: Failed hooks revert the entire operation

## Router Contract Pattern

For production use, implement a router contract to:

1. Handle token transfers and approvals
2. Provide user-friendly interfaces
3. Calculate optimal paths for multi-hop swaps
4. Implement slippage protection
5. Support ETH wrapping/unwrapping

```solidity
contract QRDXRouter {
    IPoolManager public immutable poolManager;
    
    function swapExactInput(
        PoolKey calldata poolKey,
        uint256 amountIn,
        uint256 amountOutMinimum
    ) external returns (uint256 amountOut) {
        // Transfer tokens from user
        // Execute swap on PoolManager
        // Validate output amount
        // Transfer tokens to user
    }
}
```

## Advanced Features

### Multi-Hop Swaps

Route swaps through multiple pools for better prices:

```
TokenA → TokenB → TokenC
  Pool1    Pool2
```

### Flash Swaps

Borrow tokens, use them, and pay back in same transaction:

```solidity
// Borrow TokenB without upfront TokenA
// Use TokenB
// Repay with TokenA + fee
```

### Just-In-Time Liquidity

Add liquidity immediately before large swaps, remove after:

```solidity
// beforeSwap hook: Add liquidity
// Swap executes with more liquidity (less slippage)
// afterSwap hook: Remove liquidity + collect fees
```

## Roadmap

### Phase 8 (Current)
- ✅ Core PoolManager implementation
- ✅ Tick mathematics
- ✅ Swap logic
- ✅ Position management
- ✅ Example hooks (limit orders, dynamic fees)
- ⏳ Comprehensive testing
- ⏳ Router contract

### Future Enhancements
- Advanced hooks (TWAP oracles, whitelists, MEV protection)
- Cross-chain liquidity aggregation
- Layer 2 optimizations
- Governance integration
- Protocol fee mechanisms

## Testing

See `scripts/test_qrdx_amm.py` for comprehensive test suite including:

- Pool initialization
- Swap execution and price impact
- Liquidity provision and removal
- Fee accrual and collection
- Hook functionality
- Edge cases and error conditions

## License

MIT License - See LICENSE file for details

## References

- Uniswap v3 Whitepaper: https://uniswap.org/whitepaper-v3.pdf
- Uniswap v4 Draft: https://github.com/Uniswap/v4-core
- QRDX Whitepaper: See `/docs/QRDX-Whitepaper-v2.0.md`
- Concentrated Liquidity: https://arxiv.org/abs/2106.00496

## Support

For questions, issues, or contributions:
- GitHub Issues: [repository]/issues
- Documentation: [repository]/docs
- Community: [community links]
