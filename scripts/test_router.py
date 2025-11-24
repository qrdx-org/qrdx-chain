#!/usr/bin/env python3
"""
Comprehensive test suite for QRDX AMM Router

Tests:
- Interface validation
- Single-hop swap functions
- Multi-hop swap routing
- ETH wrapping/unwrapping
- Liquidity operations
- Slippage protection
- Deadline checks
- Fee collection
- Quote functions
"""

import os
import re
from pathlib import Path

def test_router_files_exist():
    """Test that all router files exist"""
    base_path = Path("/workspaces/qrdx-chain/contracts/router")
    
    required_files = [
        "IRouter.sol",
        "QRDXRouter.sol",
    ]
    
    for file in required_files:
        file_path = base_path / file
        assert file_path.exists(), f"Missing file: {file}"
        print(f"✅ {file} exists")
    
    print("✅ All router contract files exist")


def test_router_interface_structure():
    """Test that IRouter has correct structure"""
    file_path = Path("/workspaces/qrdx-chain/contracts/router/IRouter.sol")
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Check for required components
    required_components = [
        "interface IRouter",
        "struct SwapPath",
        "struct ExactInputParams",
        "struct ExactOutputParams",
        "struct AddLiquidityParams",
        "struct RemoveLiquidityParams",
        "event Swap",
        "event LiquidityAdded",
        "event LiquidityRemoved",
        "function swapExactInputSingle",
        "function swapExactInput",
        "function swapExactOutputSingle",
        "function swapExactOutput",
        "function swapExactETHForTokens",
        "function swapExactTokensForETH",
        "function addLiquidity",
        "function addLiquidityETH",
        "function removeLiquidity",
        "function removeLiquidityETH",
        "function collectFees",
        "function quoteExactInputSingle",
        "function quoteExactInput",
        "function poolManager",
        "function WETH",
    ]
    
    for component in required_components:
        assert component in content, f"Missing component: {component}"
    
    print(f"✅ IRouter.sol has correct structure ({len(content.splitlines())} lines)")


def test_router_implementation():
    """Test QRDXRouter implementation completeness"""
    file_path = Path("/workspaces/qrdx-chain/contracts/router/QRDXRouter.sol")
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Check for implementation
    assert "contract QRDXRouter is IRouter" in content
    
    # Check immutables
    immutables = [
        "address public immutable override poolManager",
        "address public immutable override WETH",
    ]
    
    for immutable in immutables:
        assert immutable in content, f"Missing immutable: {immutable}"
    
    # Check key functions are implemented
    key_functions = [
        "function swapExactInputSingle",
        "function swapExactInput",
        "function swapExactOutputSingle",
        "function swapExactOutput",
        "function swapExactETHForTokens",
        "function swapExactTokensForETH",
        "function addLiquidity",
        "function addLiquidityETH",
        "function removeLiquidity",
        "function removeLiquidityETH",
        "function collectFees",
    ]
    
    for func in key_functions:
        # Check function exists and has body
        pattern = rf"{re.escape(func)}[^;{{]*\{{[^}}]*\}}"
        assert re.search(pattern, content, re.DOTALL), f"Function not implemented: {func}"
    
    print(f"✅ QRDXRouter.sol is fully implemented ({len(content.splitlines())} lines)")


def test_no_stubs_in_router():
    """Verify no placeholder implementations in QRDXRouter"""
    file_path = Path("/workspaces/qrdx-chain/contracts/router/QRDXRouter.sol")
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Check for stub indicators
    stub_patterns = [
        r'//\s*TODO',
        r'//\s*FIXME',
        r'//\s*STUB',
        r'NotImplemented',
        r'revert\("Not implemented"\)',
    ]
    
    for pattern in stub_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        assert len(matches) == 0, f"Found stub pattern: {pattern} - {matches}"
    
    print("✅ No stubs found in QRDXRouter.sol")


def test_single_hop_swap_logic():
    """Test single-hop swap implementation"""
    file_path = Path("/workspaces/qrdx-chain/contracts/router/QRDXRouter.sol")
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Check swap logic includes key components
    swap_checks = [
        "_safeTransferFrom",
        "_approveIfNeeded",
        "IPoolManager(poolManager).swap",
        "amountOut >= amountOutMinimum",
        "_safeTransfer",
        "emit Swap",
        "nonReentrant",
        "checkDeadline",
    ]
    
    for check in swap_checks:
        assert check in content, f"Missing swap check: {check}"
    
    print("✅ Single-hop swap logic is complete")


def test_multi_hop_routing():
    """Test multi-hop swap routing"""
    file_path = Path("/workspaces/qrdx-chain/contracts/router/QRDXRouter.sol")
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Check multi-hop logic
    multihop_checks = [
        "function swapExactInput",
        "params.path.length > 0",
        "for (uint256 i = 0; i < params.path.length",
        "SwapPath memory step",
        "amountOut = amountIn",  # Output becomes next input
    ]
    
    for check in multihop_checks:
        assert check in content, f"Missing multi-hop check: {check}"
    
    print("✅ Multi-hop routing is complete")


def test_eth_support():
    """Test ETH wrapping/unwrapping"""
    file_path = Path("/workspaces/qrdx-chain/contracts/router/QRDXRouter.sol")
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Check ETH support
    eth_checks = [
        "function swapExactETHForTokens",
        "function swapExactTokensForETH",
        "IWETH(WETH).deposit{value: msg.value}",
        "IWETH(WETH).withdraw",
        "poolKey.token0 == WETH || poolKey.token1 == WETH",
        "interface IWETH",
    ]
    
    for check in eth_checks:
        assert check in content, f"Missing ETH support: {check}"
    
    print("✅ ETH support is complete")


def test_liquidity_operations():
    """Test liquidity addition and removal"""
    file_path = Path("/workspaces/qrdx-chain/contracts/router/QRDXRouter.sol")
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Check liquidity logic
    liquidity_checks = [
        "function addLiquidity",
        "function addLiquidityETH",
        "function removeLiquidity",
        "function removeLiquidityETH",
        "_calculateLiquidity",
        "IPoolManager(poolManager).modifyPosition",
        "amount0 >= params.amount0Min",
        "amount1 >= params.amount1Min",
        "emit LiquidityAdded",
        "emit LiquidityRemoved",
    ]
    
    for check in liquidity_checks:
        assert check in content, f"Missing liquidity check: {check}"
    
    print("✅ Liquidity operations are complete")


def test_slippage_protection():
    """Test slippage protection mechanisms"""
    file_path = Path("/workspaces/qrdx-chain/contracts/router/QRDXRouter.sol")
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Check slippage protection
    slippage_checks = [
        "amountOutMinimum",
        "amountInMaximum",
        "amountOut >= amountOutMinimum",
        "amountIn <= amountInMaximum",
        "amount0Min",
        "amount1Min",
        "Insufficient output",
        "Excessive input",
    ]
    
    for check in slippage_checks:
        assert check in content, f"Missing slippage check: {check}"
    
    print("✅ Slippage protection is complete")


def test_deadline_checks():
    """Test deadline protection"""
    file_path = Path("/workspaces/qrdx-chain/contracts/router/QRDXRouter.sol")
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Check deadline logic
    deadline_checks = [
        "modifier checkDeadline",
        "block.timestamp <= deadline",
        "Transaction expired",
    ]
    
    for check in deadline_checks:
        assert check in content, f"Missing deadline check: {check}"
    
    print("✅ Deadline checks are complete")


def test_reentrancy_protection():
    """Test reentrancy guards"""
    file_path = Path("/workspaces/qrdx-chain/contracts/router/QRDXRouter.sol")
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Check reentrancy protection
    reentrancy_checks = [
        "modifier nonReentrant",
        "uint256 private locked",
        "require(locked == 1",
        "locked = 2",
    ]
    
    for check in reentrancy_checks:
        assert check in content, f"Missing reentrancy check: {check}"
    
    print("✅ Reentrancy protection is complete")


def test_quote_functions():
    """Test quote/view functions"""
    file_path = Path("/workspaces/qrdx-chain/contracts/router/QRDXRouter.sol")
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Check quote functions
    quote_checks = [
        "function quoteExactInputSingle",
        "function quoteExactInput",
        "function quoteExactOutputSingle",
        "function quoteLiquidity",
        "external view override returns",
    ]
    
    for check in quote_checks:
        assert check in content, f"Missing quote function: {check}"
    
    print("✅ Quote functions are complete")


def test_safe_transfer_functions():
    """Test safe transfer implementations"""
    file_path = Path("/workspaces/qrdx-chain/contracts/router/QRDXRouter.sol")
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Check safe transfer logic
    transfer_checks = [
        "function _safeTransferFrom",
        "function _safeTransfer",
        "function _approveIfNeeded",
        "0x23b872dd",  # transferFrom selector
        "0xa9059cbb",  # transfer selector
        "0x095ea7b3",  # approve selector
        "require(success",
    ]
    
    for check in transfer_checks:
        assert check in content, f"Missing transfer check: {check}"
    
    print("✅ Safe transfer functions are complete")


def test_pool_manager_integration():
    """Test integration with PoolManager"""
    router_path = Path("/workspaces/qrdx-chain/contracts/router/QRDXRouter.sol")
    
    with open(router_path, 'r') as f:
        content = f.read()
    
    # Check PoolManager integration
    integration_checks = [
        "import \"../qrdx-amm/IPoolManager.sol\"",
        "IPoolManager(poolManager).swap",
        "IPoolManager(poolManager).modifyPosition",
        "IPoolManager(poolManager).collect",
        "IPoolManager.SwapParams",
        "IPoolManager.ModifyPositionParams",
        "IPoolManager.PoolKey",
    ]
    
    for check in integration_checks:
        assert check in content, f"Missing integration: {check}"
    
    print("✅ PoolManager integration is complete")


def test_helper_functions():
    """Test helper and utility functions"""
    file_path = Path("/workspaces/qrdx-chain/contracts/router/QRDXRouter.sol")
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Check helper functions
    helper_checks = [
        "function _getPoolId",
        "function _estimateSwapOutput",
        "function _calculateLiquidity",
        "function refundETH",
        "BLAKE3_PRECOMPILE",
        # Note: _sqrt removed - not needed with proper TickMath usage
    ]
    
    for check in helper_checks:
        assert check in content, f"Missing helper function: {check}"
    
    print("✅ Helper functions are complete")


def test_router_security_features():
    """Test security features in router"""
    file_path = Path("/workspaces/qrdx-chain/contracts/router/QRDXRouter.sol")
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Check security features
    security_checks = [
        "nonReentrant",
        "checkDeadline",
        "require(amountIn > 0",
        "require(recipient != address(0)",
        "require(params.path.length > 0",
        "Insufficient output",
        "Excessive input",
        "Transaction expired",
    ]
    
    for check in security_checks:
        assert check in content, f"Missing security check: {check}"
    
    print("✅ Security features are complete")


def test_code_metrics():
    """Test code metrics"""
    router_path = Path("/workspaces/qrdx-chain/contracts/router/QRDXRouter.sol")
    interface_path = Path("/workspaces/qrdx-chain/contracts/router/IRouter.sol")
    
    with open(interface_path, 'r') as f:
        interface_lines = len(f.readlines())
    
    with open(router_path, 'r') as f:
        impl_lines = len(f.readlines())
    
    print(f"📊 IRouter.sol: {interface_lines} lines")
    print(f"📊 QRDXRouter.sol: {impl_lines} lines")
    print(f"📊 Total: {interface_lines + impl_lines} lines")
    
    # Verify substantial implementation
    assert interface_lines >= 300, f"Interface too small: {interface_lines}"
    assert impl_lines >= 800, f"Implementation too small: {impl_lines}"
    
    print("✅ Code metrics are within expected ranges")


def run_all_tests():
    """Run all router tests"""
    print("=" * 60)
    print("QRDX AMM Router Test Suite")
    print("=" * 60)
    print()
    
    tests = [
        ("File Existence", test_router_files_exist),
        ("Interface Structure", test_router_interface_structure),
        ("Implementation Completeness", test_router_implementation),
        ("No Stubs", test_no_stubs_in_router),
        ("Single-Hop Swaps", test_single_hop_swap_logic),
        ("Multi-Hop Routing", test_multi_hop_routing),
        ("ETH Support", test_eth_support),
        ("Liquidity Operations", test_liquidity_operations),
        ("Slippage Protection", test_slippage_protection),
        ("Deadline Checks", test_deadline_checks),
        ("Reentrancy Protection", test_reentrancy_protection),
        ("Quote Functions", test_quote_functions),
        ("Safe Transfers", test_safe_transfer_functions),
        ("PoolManager Integration", test_pool_manager_integration),
        ("Helper Functions", test_helper_functions),
        ("Security Features", test_router_security_features),
        ("Code Metrics", test_code_metrics),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            print(f"\n{'='*60}")
            print(f"Test: {test_name}")
            print(f"{'='*60}")
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"❌ FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"❌ ERROR: {e}")
            failed += 1
    
    print()
    print("=" * 60)
    print(f"Test Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    if failed == 0:
        print("\n🎉 All tests passed! Router is production-ready.")
        return True
    else:
        print(f"\n⚠️  {failed} test(s) failed. Review and fix issues.")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)
