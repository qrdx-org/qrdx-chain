// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../qrdx-amm/IPoolManager.sol";

/**
 * @title IRouter
 * @notice Interface for QRDX AMM Router
 * @dev User-friendly interface for interacting with the PoolManager singleton.
 * Handles token transfers, slippage protection, multi-hop swaps, and ETH wrapping.
 * 
 * Key Features:
 * - Single and multi-hop swaps
 * - Exact input and exact output swap variants
 * - Liquidity provision and removal
 * - Slippage protection via minimum output amounts
 * - Deadline-based transaction expiry
 * - ETH support via WETH wrapping
 * - Fee collection for liquidity providers
 */
interface IRouter {
    
    // ============ Structs ============
    
    /**
     * @notice Path element for multi-hop swaps
     * @param poolKey Pool identification
     * @param zeroForOne Swap direction
     */
    struct SwapPath {
        IPoolManager.PoolKey poolKey;
        bool zeroForOne;
    }
    
    /**
     * @notice Parameters for exact input swap
     * @param path Array of pool keys and directions
     * @param recipient Address receiving output tokens
     * @param deadline Transaction deadline timestamp
     * @param amountIn Exact input amount
     * @param amountOutMinimum Minimum acceptable output (slippage protection)
     */
    struct ExactInputParams {
        SwapPath[] path;
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;
    }
    
    /**
     * @notice Parameters for exact output swap
     * @param path Array of pool keys and directions
     * @param recipient Address receiving output tokens
     * @param deadline Transaction deadline timestamp
     * @param amountOut Exact output amount desired
     * @param amountInMaximum Maximum acceptable input (slippage protection)
     */
    struct ExactOutputParams {
        SwapPath[] path;
        address recipient;
        uint256 deadline;
        uint256 amountOut;
        uint256 amountInMaximum;
    }
    
    /**
     * @notice Parameters for adding liquidity
     * @param poolKey Pool identification
     * @param tickLower Lower tick of position
     * @param tickUpper Upper tick of position
     * @param amount0Desired Desired amount of token0
     * @param amount1Desired Desired amount of token1
     * @param amount0Min Minimum amount of token0 (slippage)
     * @param amount1Min Minimum amount of token1 (slippage)
     * @param recipient Address receiving liquidity position
     * @param deadline Transaction deadline
     */
    struct AddLiquidityParams {
        IPoolManager.PoolKey poolKey;
        int24 tickLower;
        int24 tickUpper;
        uint256 amount0Desired;
        uint256 amount1Desired;
        uint256 amount0Min;
        uint256 amount1Min;
        address recipient;
        uint256 deadline;
    }
    
    /**
     * @notice Parameters for removing liquidity
     * @param poolKey Pool identification
     * @param tickLower Lower tick of position
     * @param tickUpper Upper tick of position
     * @param liquidity Amount of liquidity to remove
     * @param amount0Min Minimum token0 to receive
     * @param amount1Min Minimum token1 to receive
     * @param recipient Address receiving tokens
     * @param deadline Transaction deadline
     */
    struct RemoveLiquidityParams {
        IPoolManager.PoolKey poolKey;
        int24 tickLower;
        int24 tickUpper;
        uint128 liquidity;
        uint256 amount0Min;
        uint256 amount1Min;
        address recipient;
        uint256 deadline;
    }
    
    // ============ Events ============
    
    /**
     * @notice Emitted on successful swap
     * @param sender Address initiating swap
     * @param recipient Address receiving tokens
     * @param amountIn Input amount
     * @param amountOut Output amount
     * @param path Swap path taken
     */
    event Swap(
        address indexed sender,
        address indexed recipient,
        uint256 amountIn,
        uint256 amountOut,
        SwapPath[] path
    );
    
    /**
     * @notice Emitted when liquidity is added
     * @param poolId Pool identifier
     * @param sender Address adding liquidity
     * @param recipient Position owner
     * @param tickLower Lower tick
     * @param tickUpper Upper tick
     * @param liquidity Liquidity amount
     * @param amount0 Token0 amount
     * @param amount1 Token1 amount
     */
    event LiquidityAdded(
        bytes32 indexed poolId,
        address indexed sender,
        address indexed recipient,
        int24 tickLower,
        int24 tickUpper,
        uint128 liquidity,
        uint256 amount0,
        uint256 amount1
    );
    
    /**
     * @notice Emitted when liquidity is removed
     * @param poolId Pool identifier
     * @param sender Address removing liquidity
     * @param recipient Token receiver
     * @param tickLower Lower tick
     * @param tickUpper Upper tick
     * @param liquidity Liquidity amount
     * @param amount0 Token0 amount
     * @param amount1 Token1 amount
     */
    event LiquidityRemoved(
        bytes32 indexed poolId,
        address indexed sender,
        address indexed recipient,
        int24 tickLower,
        int24 tickUpper,
        uint128 liquidity,
        uint256 amount0,
        uint256 amount1
    );
    
    // ============ Swap Functions ============
    
    /**
     * @notice Swap exact input for maximum possible output (single hop)
     * @param poolKey Pool to swap through
     * @param zeroForOne Swap direction (true = token0 -> token1)
     * @param amountIn Exact input amount
     * @param amountOutMinimum Minimum output amount (slippage protection)
     * @param recipient Address receiving output tokens
     * @param deadline Transaction must execute before this timestamp
     * @return amountOut Actual output amount received
     */
    function swapExactInputSingle(
        IPoolManager.PoolKey calldata poolKey,
        bool zeroForOne,
        uint256 amountIn,
        uint256 amountOutMinimum,
        address recipient,
        uint256 deadline
    ) external returns (uint256 amountOut);
    
    /**
     * @notice Swap exact input for maximum possible output (multi-hop)
     * @param params Swap parameters including path
     * @return amountOut Total output amount received
     */
    function swapExactInput(
        ExactInputParams calldata params
    ) external returns (uint256 amountOut);
    
    /**
     * @notice Swap minimum possible input for exact output (single hop)
     * @param poolKey Pool to swap through
     * @param zeroForOne Swap direction
     * @param amountOut Exact output amount desired
     * @param amountInMaximum Maximum input amount willing to spend
     * @param recipient Address receiving output tokens
     * @param deadline Transaction deadline
     * @return amountIn Actual input amount spent
     */
    function swapExactOutputSingle(
        IPoolManager.PoolKey calldata poolKey,
        bool zeroForOne,
        uint256 amountOut,
        uint256 amountInMaximum,
        address recipient,
        uint256 deadline
    ) external returns (uint256 amountIn);
    
    /**
     * @notice Swap minimum possible input for exact output (multi-hop)
     * @param params Swap parameters including path
     * @return amountIn Total input amount spent
     */
    function swapExactOutput(
        ExactOutputParams calldata params
    ) external returns (uint256 amountIn);
    
    // ============ ETH Swap Functions ============
    
    /**
     * @notice Swap exact ETH for tokens
     * @dev Wraps ETH to WETH automatically
     * @param poolKey Pool to swap through
     * @param amountOutMinimum Minimum output tokens
     * @param recipient Address receiving tokens
     * @param deadline Transaction deadline
     * @return amountOut Tokens received
     */
    function swapExactETHForTokens(
        IPoolManager.PoolKey calldata poolKey,
        uint256 amountOutMinimum,
        address recipient,
        uint256 deadline
    ) external payable returns (uint256 amountOut);
    
    /**
     * @notice Swap exact tokens for ETH
     * @dev Unwraps WETH to ETH automatically
     * @param poolKey Pool to swap through
     * @param amountIn Exact token input
     * @param amountOutMinimum Minimum ETH output
     * @param recipient Address receiving ETH
     * @param deadline Transaction deadline
     * @return amountOut ETH received
     */
    function swapExactTokensForETH(
        IPoolManager.PoolKey calldata poolKey,
        uint256 amountIn,
        uint256 amountOutMinimum,
        address recipient,
        uint256 deadline
    ) external returns (uint256 amountOut);
    
    // ============ Liquidity Functions ============
    
    /**
     * @notice Add liquidity to a pool
     * @param params Liquidity parameters
     * @return liquidity Amount of liquidity minted
     * @return amount0 Amount of token0 added
     * @return amount1 Amount of token1 added
     */
    function addLiquidity(
        AddLiquidityParams calldata params
    ) external returns (
        uint128 liquidity,
        uint256 amount0,
        uint256 amount1
    );
    
    /**
     * @notice Add liquidity with ETH
     * @param params Liquidity parameters (one token must be WETH)
     * @return liquidity Amount of liquidity minted
     * @return amount0 Amount of token0 added
     * @return amount1 Amount of token1 added
     */
    function addLiquidityETH(
        AddLiquidityParams calldata params
    ) external payable returns (
        uint128 liquidity,
        uint256 amount0,
        uint256 amount1
    );
    
    /**
     * @notice Remove liquidity from a pool
     * @param params Removal parameters
     * @return amount0 Amount of token0 received
     * @return amount1 Amount of token1 received
     */
    function removeLiquidity(
        RemoveLiquidityParams calldata params
    ) external returns (
        uint256 amount0,
        uint256 amount1
    );
    
    /**
     * @notice Remove liquidity and receive ETH
     * @param params Removal parameters (one token must be WETH)
     * @return amount0 Amount of token0 received (or ETH)
     * @return amount1 Amount of token1 received (or ETH)
     */
    function removeLiquidityETH(
        RemoveLiquidityParams calldata params
    ) external returns (
        uint256 amount0,
        uint256 amount1
    );
    
    /**
     * @notice Collect accumulated fees from a position
     * @param poolKey Pool identification
     * @param tickLower Lower tick
     * @param tickUpper Upper tick
     * @param recipient Address receiving fees
     * @return amount0 Token0 fees collected
     * @return amount1 Token1 fees collected
     */
    function collectFees(
        IPoolManager.PoolKey calldata poolKey,
        int24 tickLower,
        int24 tickUpper,
        address recipient
    ) external returns (
        uint256 amount0,
        uint256 amount1
    );
    
    // ============ Quote Functions (View) ============
    
    /**
     * @notice Get quote for exact input swap (single hop)
     * @param poolKey Pool to query
     * @param zeroForOne Swap direction
     * @param amountIn Input amount
     * @return amountOut Expected output amount
     */
    function quoteExactInputSingle(
        IPoolManager.PoolKey calldata poolKey,
        bool zeroForOne,
        uint256 amountIn
    ) external view returns (uint256 amountOut);
    
    /**
     * @notice Get quote for exact input swap (multi-hop)
     * @param path Swap path
     * @param amountIn Input amount
     * @return amountOut Expected output amount
     */
    function quoteExactInput(
        SwapPath[] calldata path,
        uint256 amountIn
    ) external view returns (uint256 amountOut);
    
    /**
     * @notice Get quote for exact output swap (single hop)
     * @param poolKey Pool to query
     * @param zeroForOne Swap direction
     * @param amountOut Desired output amount
     * @return amountIn Required input amount
     */
    function quoteExactOutputSingle(
        IPoolManager.PoolKey calldata poolKey,
        bool zeroForOne,
        uint256 amountOut
    ) external view returns (uint256 amountIn);
    
    /**
     * @notice Calculate liquidity for token amounts
     * @param poolKey Pool identification
     * @param tickLower Lower tick
     * @param tickUpper Upper tick
     * @param amount0 Token0 amount
     * @param amount1 Token1 amount
     * @return liquidity Expected liquidity amount
     */
    function quoteLiquidity(
        IPoolManager.PoolKey calldata poolKey,
        int24 tickLower,
        int24 tickUpper,
        uint256 amount0,
        uint256 amount1
    ) external view returns (uint128 liquidity);
    
    // ============ Helper Functions ============
    
    /**
     * @notice Get pool manager address
     * @return Address of PoolManager singleton
     */
    function poolManager() external view returns (address);
    
    /**
     * @notice Get WETH address
     * @return Address of Wrapped ETH contract
     */
    function WETH() external view returns (address);
    
    /**
     * @notice Refund excess ETH to sender
     * @dev Called internally after ETH swaps
     */
    function refundETH() external payable;
}
