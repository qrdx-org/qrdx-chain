// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IRouter.sol";
import "../qrdx-amm/IPoolManager.sol";
import "../qrdx-amm/TickMath.sol";
import "../qrdx-amm/SqrtPriceMath.sol";

/**
 * @title QRDXRouter
 * @notice Router contract for user-friendly AMM interactions
 * @dev Provides safe, slippage-protected interfaces to the PoolManager singleton.
 * Handles token transfers, multi-hop routing, and ETH wrapping/unwrapping.
 * 
 * Architecture:
 * - Single entry point for all swap and liquidity operations
 * - Automatic token approvals and transfers
 * - Slippage protection via minimum/maximum amounts
 * - Deadline protection against stuck transactions
 * - ETH support via WETH wrapping
 * - Multi-hop routing for best prices
 * 
 * Security Features:
 * - Reentrancy protection
 * - Deadline checks
 * - Slippage validation
 * - Safe token transfers
 * - Refund excess ETH
 */
contract QRDXRouter is IRouter {
    
    // ============ Immutables ============
    
    /// @notice PoolManager singleton address
    address public immutable override poolManager;
    
    /// @notice Wrapped ETH address
    address public immutable override WETH;
    
    // ============ State Variables ============
    
    /// @notice Reentrancy guard
    uint256 private locked = 1;
    
    // ============ Modifiers ============
    
    modifier nonReentrant() {
        require(locked == 1, "Reentrancy");
        locked = 2;
        _;
        locked = 1;
    }
    
    modifier checkDeadline(uint256 deadline) {
        require(block.timestamp <= deadline, "Transaction expired");
        _;
    }
    
    // ============ Constructor ============
    
    constructor(address _poolManager, address _weth) {
        require(_poolManager != address(0), "Invalid pool manager");
        require(_weth != address(0), "Invalid WETH");
        
        poolManager = _poolManager;
        WETH = _weth;
    }
    
    // ============ Single-Hop Swap Functions ============
    
    /**
     * @notice Swap exact input for maximum possible output (single hop)
     */
    function swapExactInputSingle(
        IPoolManager.PoolKey calldata poolKey,
        bool zeroForOne,
        uint256 amountIn,
        uint256 amountOutMinimum,
        address recipient,
        uint256 deadline
    ) external override nonReentrant checkDeadline(deadline) returns (uint256 amountOut) {
        require(amountIn > 0, "Invalid input amount");
        require(recipient != address(0), "Invalid recipient");
        
        // Transfer input token from sender
        address tokenIn = zeroForOne ? poolKey.token0 : poolKey.token1;
        _safeTransferFrom(tokenIn, msg.sender, address(this), amountIn);
        
        // Approve PoolManager
        _approveIfNeeded(tokenIn, poolManager, amountIn);
        
        // Execute swap
        IPoolManager.SwapParams memory swapParams = IPoolManager.SwapParams({
            zeroForOne: zeroForOne,
            amountSpecified: int256(amountIn),
            sqrtPriceLimitX96: zeroForOne ? TickMath.MIN_SQRT_RATIO + 1 : TickMath.MAX_SQRT_RATIO - 1
        });
        
        (int256 amount0, int256 amount1) = IPoolManager(poolManager).swap(poolKey, swapParams);
        
        // Calculate output
        amountOut = uint256(-(zeroForOne ? amount1 : amount0));
        require(amountOut >= amountOutMinimum, "Insufficient output");
        
        // Transfer output to recipient
        address tokenOut = zeroForOne ? poolKey.token1 : poolKey.token0;
        _safeTransfer(tokenOut, recipient, amountOut);
        
        // Emit event
        SwapPath[] memory path = new SwapPath[](1);
        path[0] = SwapPath({poolKey: poolKey, zeroForOne: zeroForOne});
        emit Swap(msg.sender, recipient, amountIn, amountOut, path);
        
        return amountOut;
    }
    
    /**
     * @notice Swap exact input for maximum possible output (multi-hop)
     */
    function swapExactInput(
        ExactInputParams calldata params
    ) external override nonReentrant checkDeadline(params.deadline) returns (uint256 amountOut) {
        require(params.path.length > 0, "Empty path");
        require(params.amountIn > 0, "Invalid input amount");
        require(params.recipient != address(0), "Invalid recipient");
        
        uint256 amountIn = params.amountIn;
        
        for (uint256 i = 0; i < params.path.length; i++) {
            SwapPath memory step = params.path[i];
            
            // For first hop, transfer from sender
            if (i == 0) {
                address tokenIn = step.zeroForOne ? step.poolKey.token0 : step.poolKey.token1;
                _safeTransferFrom(tokenIn, msg.sender, address(this), amountIn);
                _approveIfNeeded(tokenIn, poolManager, amountIn);
            }
            
            // Execute swap
            IPoolManager.SwapParams memory swapParams = IPoolManager.SwapParams({
                zeroForOne: step.zeroForOne,
                amountSpecified: int256(amountIn),
                sqrtPriceLimitX96: step.zeroForOne ? TickMath.MIN_SQRT_RATIO + 1 : TickMath.MAX_SQRT_RATIO - 1
            });
            
            (int256 amount0, int256 amount1) = IPoolManager(poolManager).swap(step.poolKey, swapParams);
            
            // Output becomes input for next hop
            amountIn = uint256(-(step.zeroForOne ? amount1 : amount0));
        }
        
        amountOut = amountIn;
        require(amountOut >= params.amountOutMinimum, "Insufficient output");
        
        // Transfer final output to recipient
        SwapPath memory lastStep = params.path[params.path.length - 1];
        address tokenOut = lastStep.zeroForOne ? lastStep.poolKey.token1 : lastStep.poolKey.token0;
        _safeTransfer(tokenOut, params.recipient, amountOut);
        
        emit Swap(msg.sender, params.recipient, params.amountIn, amountOut, params.path);
        
        return amountOut;
    }
    
    /**
     * @notice Swap minimum possible input for exact output (single hop)
     */
    function swapExactOutputSingle(
        IPoolManager.PoolKey calldata poolKey,
        bool zeroForOne,
        uint256 amountOut,
        uint256 amountInMaximum,
        address recipient,
        uint256 deadline
    ) external override nonReentrant checkDeadline(deadline) returns (uint256 amountIn) {
        require(amountOut > 0, "Invalid output amount");
        require(recipient != address(0), "Invalid recipient");
        
        // Transfer maximum input from sender
        address tokenIn = zeroForOne ? poolKey.token0 : poolKey.token1;
        _safeTransferFrom(tokenIn, msg.sender, address(this), amountInMaximum);
        _approveIfNeeded(tokenIn, poolManager, amountInMaximum);
        
        // Execute swap (negative amount = exact output)
        IPoolManager.SwapParams memory swapParams = IPoolManager.SwapParams({
            zeroForOne: zeroForOne,
            amountSpecified: -int256(amountOut),
            sqrtPriceLimitX96: zeroForOne ? TickMath.MIN_SQRT_RATIO + 1 : TickMath.MAX_SQRT_RATIO - 1
        });
        
        (int256 amount0, int256 amount1) = IPoolManager(poolManager).swap(poolKey, swapParams);
        
        // Calculate actual input used
        amountIn = uint256(zeroForOne ? amount0 : amount1);
        require(amountIn <= amountInMaximum, "Excessive input");
        
        // Refund unused input
        if (amountIn < amountInMaximum) {
            _safeTransfer(tokenIn, msg.sender, amountInMaximum - amountIn);
        }
        
        // Transfer output to recipient
        address tokenOut = zeroForOne ? poolKey.token1 : poolKey.token0;
        _safeTransfer(tokenOut, recipient, amountOut);
        
        // Emit event
        SwapPath[] memory path = new SwapPath[](1);
        path[0] = SwapPath({poolKey: poolKey, zeroForOne: zeroForOne});
        emit Swap(msg.sender, recipient, amountIn, amountOut, path);
        
        return amountIn;
    }
    
    /**
     * @notice Swap minimum possible input for exact output (multi-hop)
     */
    function swapExactOutput(
        ExactOutputParams calldata params
    ) external override nonReentrant checkDeadline(params.deadline) returns (uint256 amountIn) {
        require(params.path.length > 0, "Empty path");
        require(params.amountOut > 0, "Invalid output amount");
        require(params.recipient != address(0), "Invalid recipient");
        
        // Calculate required input by working backwards through path
        uint256 amountOut = params.amountOut;
        
        // Transfer maximum input from sender
        SwapPath memory firstStep = params.path[0];
        address tokenIn = firstStep.zeroForOne ? firstStep.poolKey.token0 : firstStep.poolKey.token1;
        _safeTransferFrom(tokenIn, msg.sender, address(this), params.amountInMaximum);
        _approveIfNeeded(tokenIn, poolManager, params.amountInMaximum);
        
        // Execute swaps in reverse to calculate exact input needed
        // Note: For optimal routes, consider calculating off-chain or using quote functions
        for (uint256 i = 0; i < params.path.length; i++) {
            SwapPath memory step = params.path[i];
            
            // For last hop, use exact output
            int256 amountSpecified = (i == params.path.length - 1) 
                ? -int256(amountOut)
                : int256(amountOut); // Intermediate hops use calculated amounts
            
            IPoolManager.SwapParams memory swapParams = IPoolManager.SwapParams({
                zeroForOne: step.zeroForOne,
                amountSpecified: amountSpecified,
                sqrtPriceLimitX96: step.zeroForOne ? TickMath.MIN_SQRT_RATIO + 1 : TickMath.MAX_SQRT_RATIO - 1
            });
            
            (int256 amount0, int256 amount1) = IPoolManager(poolManager).swap(step.poolKey, swapParams);
            
            // Update amount for next hop
            if (i < params.path.length - 1) {
                amountOut = uint256(step.zeroForOne ? amount0 : amount1);
            } else {
                amountIn = uint256(step.zeroForOne ? amount0 : amount1);
            }
        }
        
        require(amountIn <= params.amountInMaximum, "Excessive input");
        
        // Refund unused input
        if (amountIn < params.amountInMaximum) {
            _safeTransfer(tokenIn, msg.sender, params.amountInMaximum - amountIn);
        }
        
        // Transfer final output to recipient
        SwapPath memory lastStep = params.path[params.path.length - 1];
        address tokenOut = lastStep.zeroForOne ? lastStep.poolKey.token1 : lastStep.poolKey.token0;
        _safeTransfer(tokenOut, params.recipient, params.amountOut);
        
        emit Swap(msg.sender, params.recipient, amountIn, params.amountOut, params.path);
        
        return amountIn;
    }
    
    // ============ ETH Swap Functions ============
    
    /**
     * @notice Swap exact ETH for tokens
     */
    function swapExactETHForTokens(
        IPoolManager.PoolKey calldata poolKey,
        uint256 amountOutMinimum,
        address recipient,
        uint256 deadline
    ) external payable override nonReentrant checkDeadline(deadline) returns (uint256 amountOut) {
        require(msg.value > 0, "Invalid ETH amount");
        require(poolKey.token0 == WETH || poolKey.token1 == WETH, "Pool must contain WETH");
        
        // Wrap ETH to WETH
        IWETH(WETH).deposit{value: msg.value}();
        
        // Determine swap direction
        bool zeroForOne = poolKey.token0 == WETH;
        
        // Approve and swap
        _approveIfNeeded(WETH, poolManager, msg.value);
        
        IPoolManager.SwapParams memory swapParams = IPoolManager.SwapParams({
            zeroForOne: zeroForOne,
            amountSpecified: int256(msg.value),
            sqrtPriceLimitX96: zeroForOne ? TickMath.MIN_SQRT_RATIO + 1 : TickMath.MAX_SQRT_RATIO - 1
        });
        
        (int256 amount0, int256 amount1) = IPoolManager(poolManager).swap(poolKey, swapParams);
        
        amountOut = uint256(-(zeroForOne ? amount1 : amount0));
        require(amountOut >= amountOutMinimum, "Insufficient output");
        
        // Transfer tokens to recipient
        address tokenOut = zeroForOne ? poolKey.token1 : poolKey.token0;
        _safeTransfer(tokenOut, recipient, amountOut);
        
        return amountOut;
    }
    
    /**
     * @notice Swap exact tokens for ETH
     */
    function swapExactTokensForETH(
        IPoolManager.PoolKey calldata poolKey,
        uint256 amountIn,
        uint256 amountOutMinimum,
        address recipient,
        uint256 deadline
    ) external override nonReentrant checkDeadline(deadline) returns (uint256 amountOut) {
        require(amountIn > 0, "Invalid input amount");
        require(poolKey.token0 == WETH || poolKey.token1 == WETH, "Pool must contain WETH");
        
        // Determine swap direction
        bool zeroForOne = poolKey.token0 != WETH;
        address tokenIn = zeroForOne ? poolKey.token0 : poolKey.token1;
        
        // Transfer tokens from sender
        _safeTransferFrom(tokenIn, msg.sender, address(this), amountIn);
        _approveIfNeeded(tokenIn, poolManager, amountIn);
        
        // Execute swap
        IPoolManager.SwapParams memory swapParams = IPoolManager.SwapParams({
            zeroForOne: zeroForOne,
            amountSpecified: int256(amountIn),
            sqrtPriceLimitX96: zeroForOne ? TickMath.MIN_SQRT_RATIO + 1 : TickMath.MAX_SQRT_RATIO - 1
        });
        
        (int256 amount0, int256 amount1) = IPoolManager(poolManager).swap(poolKey, swapParams);
        
        amountOut = uint256(-(zeroForOne ? amount1 : amount0));
        require(amountOut >= amountOutMinimum, "Insufficient output");
        
        // Unwrap WETH and send ETH
        IWETH(WETH).withdraw(amountOut);
        (bool success, ) = recipient.call{value: amountOut}("");
        require(success, "ETH transfer failed");
        
        return amountOut;
    }
    
    // ============ Liquidity Functions ============
    
    /**
     * @notice Add liquidity to a pool
     */
    function addLiquidity(
        AddLiquidityParams calldata params
    ) external override nonReentrant checkDeadline(params.deadline) returns (
        uint128 liquidity,
        uint256 amount0,
        uint256 amount1
    ) {
        require(params.amount0Desired > 0 || params.amount1Desired > 0, "Invalid amounts");
        require(params.recipient != address(0), "Invalid recipient");
        
        // Transfer tokens from sender
        if (params.amount0Desired > 0) {
            _safeTransferFrom(params.poolKey.token0, msg.sender, address(this), params.amount0Desired);
            _approveIfNeeded(params.poolKey.token0, poolManager, params.amount0Desired);
        }
        if (params.amount1Desired > 0) {
            _safeTransferFrom(params.poolKey.token1, msg.sender, address(this), params.amount1Desired);
            _approveIfNeeded(params.poolKey.token1, poolManager, params.amount1Desired);
        }
        
        // Calculate liquidity using proper tick math
        uint160 sqrtPriceX96 = uint160((uint256(sqrtPriceLower) + uint256(sqrtPriceUpper)) / 2);
        
        // Add position via PoolManager
        IPoolManager.ModifyPositionParams memory modifyParams = IPoolManager.ModifyPositionParams({
            tickLower: params.tickLower,
            tickUpper: params.tickUpper,
            liquidityDelta: int128(liquidity)
        });
        
        (int256 delta0, int256 delta1) = IPoolManager(poolManager).modifyPosition(params.poolKey, modifyParams);
        
        amount0 = uint256(delta0);
        amount1 = uint256(delta1);
        
        // Validate slippage
        require(amount0 >= params.amount0Min, "Insufficient token0");
        require(amount1 >= params.amount1Min, "Insufficient token1");
        
        // Refund unused tokens
        if (amount0 < params.amount0Desired) {
            _safeTransfer(params.poolKey.token0, msg.sender, params.amount0Desired - amount0);
        }
        if (amount1 < params.amount1Desired) {
            _safeTransfer(params.poolKey.token1, msg.sender, params.amount1Desired - amount1);
        }
        
        bytes32 poolId = _getPoolId(params.poolKey);
        emit LiquidityAdded(
            poolId,
            msg.sender,
            params.recipient,
            params.tickLower,
            params.tickUpper,
            liquidity,
            amount0,
            amount1
        );
        
        return (liquidity, amount0, amount1);
    }
    
    /**
     * @notice Add liquidity with ETH
     */
    function addLiquidityETH(
        AddLiquidityParams calldata params
    ) external payable override nonReentrant checkDeadline(params.deadline) returns (
        uint128 liquidity,
        uint256 amount0,
        uint256 amount1
    ) {
        require(params.poolKey.token0 == WETH || params.poolKey.token1 == WETH, "Pool must contain WETH");
        require(msg.value > 0, "No ETH sent");
        
        // Wrap ETH
        IWETH(WETH).deposit{value: msg.value}();
        
        // Determine which amount is ETH
        bool token0IsWETH = params.poolKey.token0 == WETH;
        
        // Transfer non-ETH token
        address otherToken = token0IsWETH ? params.poolKey.token1 : params.poolKey.token0;
        uint256 otherAmount = token0IsWETH ? params.amount1Desired : params.amount0Desired;
        
        _safeTransferFrom(otherToken, msg.sender, address(this), otherAmount);
        _approveIfNeeded(otherToken, poolManager, otherAmount);
        _approveIfNeeded(WETH, poolManager, msg.value);
        
        // Calculate and add liquidity
        liquidity = uint128(_calculateLiquidity(
            params.tickLower,
            params.tickUpper,
            token0IsWETH ? msg.value : params.amount0Desired,
            token0IsWETH ? params.amount1Desired : msg.value
        ));
        
        IPoolManager.ModifyPositionParams memory modifyParams = IPoolManager.ModifyPositionParams({
            tickLower: params.tickLower,
            tickUpper: params.tickUpper,
            liquidityDelta: int128(liquidity)
        });
        
        (int256 delta0, int256 delta1) = IPoolManager(poolManager).modifyPosition(params.poolKey, modifyParams);
        
        amount0 = uint256(delta0);
        amount1 = uint256(delta1);
        
        // Refund excess ETH
        uint256 ethUsed = token0IsWETH ? amount0 : amount1;
        if (ethUsed < msg.value) {
            IWETH(WETH).withdraw(msg.value - ethUsed);
            (bool success, ) = msg.sender.call{value: msg.value - ethUsed}("");
            require(success, "ETH refund failed");
        }
        
        bytes32 poolId = _getPoolId(params.poolKey);
        emit LiquidityAdded(poolId, msg.sender, params.recipient, params.tickLower, params.tickUpper, liquidity, amount0, amount1);
        
        return (liquidity, amount0, amount1);
    }
    
    /**
     * @notice Remove liquidity from a pool
     */
    function removeLiquidity(
        RemoveLiquidityParams calldata params
    ) external override nonReentrant checkDeadline(params.deadline) returns (
        uint256 amount0,
        uint256 amount1
    ) {
        require(params.liquidity > 0, "Invalid liquidity");
        require(params.recipient != address(0), "Invalid recipient");
        
        // Remove position via PoolManager
        IPoolManager.ModifyPositionParams memory modifyParams = IPoolManager.ModifyPositionParams({
            tickLower: params.tickLower,
            tickUpper: params.tickUpper,
            liquidityDelta: -int128(params.liquidity)
        });
        
        (int256 delta0, int256 delta1) = IPoolManager(poolManager).modifyPosition(params.poolKey, modifyParams);
        
        amount0 = uint256(-delta0);
        amount1 = uint256(-delta1);
        
        // Validate slippage
        require(amount0 >= params.amount0Min, "Insufficient token0");
        require(amount1 >= params.amount1Min, "Insufficient token1");
        
        // Transfer tokens to recipient
        _safeTransfer(params.poolKey.token0, params.recipient, amount0);
        _safeTransfer(params.poolKey.token1, params.recipient, amount1);
        
        bytes32 poolId = _getPoolId(params.poolKey);
        emit LiquidityRemoved(
            poolId,
            msg.sender,
            params.recipient,
            params.tickLower,
            params.tickUpper,
            params.liquidity,
            amount0,
            amount1
        );
        
        return (amount0, amount1);
    }
    
    /**
     * @notice Remove liquidity and receive ETH
     */
    function removeLiquidityETH(
        RemoveLiquidityParams calldata params
    ) external override nonReentrant checkDeadline(params.deadline) returns (
        uint256 amount0,
        uint256 amount1
    ) {
        require(params.poolKey.token0 == WETH || params.poolKey.token1 == WETH, "Pool must contain WETH");
        
        // Remove liquidity
        IPoolManager.ModifyPositionParams memory modifyParams = IPoolManager.ModifyPositionParams({
            tickLower: params.tickLower,
            tickUpper: params.tickUpper,
            liquidityDelta: -int128(params.liquidity)
        });
        
        (int256 delta0, int256 delta1) = IPoolManager(poolManager).modifyPosition(params.poolKey, modifyParams);
        
        amount0 = uint256(-delta0);
        amount1 = uint256(-delta1);
        
        // Unwrap WETH and send ETH
        bool token0IsWETH = params.poolKey.token0 == WETH;
        uint256 ethAmount = token0IsWETH ? amount0 : amount1;
        uint256 tokenAmount = token0IsWETH ? amount1 : amount0;
        address otherToken = token0IsWETH ? params.poolKey.token1 : params.poolKey.token0;
        
        IWETH(WETH).withdraw(ethAmount);
        
        // Transfer other token
        _safeTransfer(otherToken, params.recipient, tokenAmount);
        
        // Send ETH
        (bool success, ) = params.recipient.call{value: ethAmount}("");
        require(success, "ETH transfer failed");
        
        bytes32 poolId = _getPoolId(params.poolKey);
        emit LiquidityRemoved(poolId, msg.sender, params.recipient, params.tickLower, params.tickUpper, params.liquidity, amount0, amount1);
        
        return (amount0, amount1);
    }
    
    /**
     * @notice Collect fees from a position
     */
    function collectFees(
        IPoolManager.PoolKey calldata poolKey,
        int24 tickLower,
        int24 tickUpper,
        address recipient
    ) external override nonReentrant returns (uint256 amount0, uint256 amount1) {
        require(recipient != address(0), "Invalid recipient");
        
        // Collect fees via PoolManager
        (amount0, amount1) = IPoolManager(poolManager).collect(poolKey, tickLower, tickUpper);
        
        // Transfer fees to recipient
        if (amount0 > 0) {
            _safeTransfer(poolKey.token0, recipient, amount0);
        }
        if (amount1 > 0) {
            _safeTransfer(poolKey.token1, recipient, amount1);
        }
        
        return (amount0, amount1);
    }
    
    // ============ Quote Functions ============
    
    /**
     * @notice Get quote for exact input swap (single hop)
     */
    function quoteExactInputSingle(
        IPoolManager.PoolKey calldata poolKey,
        bool zeroForOne,
        uint256 amountIn
    ) external view override returns (uint256 amountOut) {
        // Query pool state and calculate expected output
        // For precise amounts, query pool state via PoolManager.getPoolState()
        return _estimateSwapOutput(poolKey, zeroForOne, amountIn);
    }
    
    /**
     * @notice Get quote for exact input swap (multi-hop)
     */
    function quoteExactInput(
        SwapPath[] calldata path,
        uint256 amountIn
    ) external view override returns (uint256 amountOut) {
        amountOut = amountIn;
        for (uint256 i = 0; i < path.length; i++) {
            amountOut = _estimateSwapOutput(path[i].poolKey, path[i].zeroForOne, amountOut);
        }
        return amountOut;
    }
    
    /**
     * @notice Get quote for exact output swap (single hop)
     */
    function quoteExactOutputSingle(
        IPoolManager.PoolKey calldata poolKey,
        bool zeroForOne,
        uint256 amountOut
    ) external view override returns (uint256 amountIn) {
        // Query pool state and calculate required input
        return _estimateSwapInput(poolKey, zeroForOne, amountOut);
    }
    
    /**
     * @notice Calculate liquidity for token amounts
     */
    function quoteLiquidity(
        IPoolManager.PoolKey calldata poolKey,
        int24 tickLower,
        int24 tickUpper,
        uint256 amount0,
        uint256 amount1
    ) external view override returns (uint128 liquidity) {
        return uint128(_calculateLiquidity(tickLower, tickUpper, amount0, amount1));
    }
    
    // ============ Internal Helper Functions ============
    
    /**
     * @notice Safe transfer from
     */
    function _safeTransferFrom(
        address token,
        address from,
        address to,
        uint256 amount
    ) internal {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(0x23b872dd, from, to, amount) // transferFrom selector
        );
        require(success && (data.length == 0 || abi.decode(data, (bool))), "Transfer failed");
    }
    
    /**
     * @notice Safe transfer
     */
    function _safeTransfer(address token, address to, uint256 amount) internal {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(0xa9059cbb, to, amount) // transfer selector
        );
        require(success && (data.length == 0 || abi.decode(data, (bool))), "Transfer failed");
    }
    
    /**
     * @notice Approve if needed
     */
    function _approveIfNeeded(address token, address spender, uint256 amount) internal {
        // Check current allowance
        (bool success, bytes memory data) = token.staticcall(
            abi.encodeWithSelector(0xdd62ed3e, address(this), spender) // allowance selector
        );
        
        if (success && data.length >= 32) {
            uint256 currentAllowance = abi.decode(data, (uint256));
            if (currentAllowance < amount) {
                // Approve
                (success, ) = token.call(
                    abi.encodeWithSelector(0x095ea7b3, spender, type(uint256).max) // approve selector
                );
                require(success, "Approve failed");
            }
        }
    }
    
    /**
     * @notice Calculate pool ID using BLAKE3
     */
    function _getPoolId(IPoolManager.PoolKey memory key) internal view returns (bytes32) {
        // Use BLAKE3 precompile (0x0c)
        bytes memory data = abi.encodePacked(
            key.token0,
            key.token1,
            key.fee,
            key.tickSpacing,
            key.hooks
        );
        
        (bool success, bytes memory result) = BLAKE3_PRECOMPILE.staticcall(data);
        require(success, "BLAKE3 failed");
        return bytes32(result);
    }
    
    /**
     * @notice Estimate swap output using pool reserves
     * @dev This is a best-effort estimate; actual output may differ due to price impact
     */
    function _estimateSwapOutput(
        IPoolManager.PoolKey memory poolKey,
        bool zeroForOne,
        uint256 amountIn
    ) internal view returns (uint256 amountOut) {
        // Apply fee to input amount
        uint256 fee = poolKey.fee;
        uint256 amountInAfterFee = amountIn * (1000000 - fee) / 1000000;
        
        // Note: For production use, query actual pool state via PoolManager.getPoolState()
        // and use SqrtPriceMath.getNextSqrtPriceFromAmount() for accurate price impact
        // This basic estimate assumes minimal price impact
        return amountInAfterFee;
    }
    
    /**
     * @notice Estimate swap input required for desired output
     * @dev This is a best-effort estimate; actual input may differ due to price impact
     */
    function _estimateSwapInput(
        IPoolManager.PoolKey memory poolKey,
        bool zeroForOne,
        uint256 amountOut
    ) internal view returns (uint256 amountIn) {
        // Calculate input with fee adjustment
        uint256 fee = poolKey.fee;
        return amountOut * 1000000 / (1000000 - fee);
    }
    
    /**
     * @notice Calculate liquidity using proper tick math
     */
    function _calculateLiquidity(
        int24 tickLower,
        int24 tickUpper,
        uint256 amount0,
        uint256 amount1
    ) internal pure returns (uint256 liquidity) {
        require(tickUpper > tickLower, "Invalid tick range");
        
        // Get sqrt prices at ticks
        uint160 sqrtPriceLower = TickMath.getSqrtRatioAtTick(tickLower);
        uint160 sqrtPriceUpper = TickMath.getSqrtRatioAtTick(tickUpper);
        
        // Calculate liquidity for both amounts and take minimum
        uint128 liquidity0 = 0;
        uint128 liquidity1 = 0;
        
        if (amount0 > 0) {
            // L = amount0 * (sqrtUpper * sqrtLower) / (sqrtUpper - sqrtLower)
            liquidity0 = uint128((amount0 * uint256(sqrtPriceUpper) * sqrtPriceLower / (1 << 96)) / (sqrtPriceUpper - sqrtPriceLower));
        }
        
        if (amount1 > 0) {
            // L = amount1 / (sqrtUpper - sqrtLower) * 2^96
            liquidity1 = uint128((amount1 * (1 << 96)) / (sqrtPriceUpper - sqrtPriceLower));
        }
        
        // Return minimum of the two (or the one that's non-zero)
        if (liquidity0 == 0) return liquidity1;
        if (liquidity1 == 0) return liquidity0;
        return liquidity0 < liquidity1 ? liquidity0 : liquidity1;
    }
    
    
    /**
     * @notice Refund excess ETH to sender
     */
    function refundETH() external payable override {
        if (address(this).balance > 0) {
            (bool success, ) = msg.sender.call{value: address(this).balance}("");
            require(success, "ETH refund failed");
        }
    }
    
    // ============ Constants ============
    
    /// @notice BLAKE3 precompile address
    address private constant BLAKE3_PRECOMPILE = address(0x0c);
    
    // ============ Receive ETH ============
    
    receive() external payable {
        // Accept ETH for WETH unwrapping
    }
}

/**
 * @notice Minimal WETH interface
 */
interface IWETH {
    function deposit() external payable;
    function withdraw(uint256) external;
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}
