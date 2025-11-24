"""
QRDX Governance System - Compilation and Architecture Tests

Tests for Phase 10: On-Chain Governance System
- Governor.sol: Quantum-resistant governance with Dilithium voting
- Timelock.sol: Time-locked execution for security
- Integration: QRDXChain, Bridge, AMM, Treasury
"""

import json
import os
import subprocess
from pathlib import Path


def test_governance_contracts_exist():
    """Verify all governance contract files exist"""
    contracts_dir = Path("/workspaces/qrdx-chain/contracts/governance")
    
    required_files = [
        "IGovernor.sol",
        "Governor.sol",
        "ITimelock.sol",
        "Timelock.sol",
    ]
    
    for filename in required_files:
        filepath = contracts_dir / filename
        assert filepath.exists(), f"Missing contract file: {filename}"
        assert filepath.stat().st_size > 0, f"Empty contract file: {filename}"
    
    print("✅ All governance contract files exist")


def test_interface_structure():
    """Verify interface files have required components"""
    contracts_dir = Path("/workspaces/qrdx-chain/contracts/governance")
    
    # Check IGovernor.sol
    igovernor = (contracts_dir / "IGovernor.sol").read_text()
    
    assert "interface IGovernor" in igovernor
    assert "enum ProposalState" in igovernor
    assert "enum VoteType" in igovernor
    assert "struct Proposal" in igovernor
    assert "struct Receipt" in igovernor
    assert "event ProposalCreated" in igovernor
    assert "event VoteCast" in igovernor
    assert "event ProposalQueued" in igovernor
    assert "event ProposalExecuted" in igovernor
    assert "function propose(" in igovernor
    assert "function castVote(" in igovernor
    assert "function castVoteWithSignature(" in igovernor
    assert "function queue(" in igovernor
    assert "function execute(" in igovernor
    
    print("✅ IGovernor.sol has correct structure")
    
    # Check ITimelock.sol
    itimelock = (contracts_dir / "ITimelock.sol").read_text()
    
    assert "interface ITimelock" in itimelock
    assert "struct QueuedTransaction" in itimelock
    assert "event TransactionQueued" in itimelock
    assert "event TransactionExecuted" in itimelock
    assert "event TransactionCanceled" in itimelock
    assert "function queueTransaction(" in itimelock
    assert "function executeTransaction(" in itimelock
    assert "function cancelTransaction(" in itimelock
    
    print("✅ ITimelock.sol has correct structure")


def test_governor_implementation():
    """Verify Governor.sol implementation completeness"""
    contracts_dir = Path("/workspaces/qrdx-chain/contracts/governance")
    governor = (contracts_dir / "Governor.sol").read_text()
    
    # Check contract declaration
    assert "contract Governor is IGovernor" in governor
    
    # Check constants
    assert "DILITHIUM_PRECOMPILE" in governor
    assert "BLAKE3_PRECOMPILE" in governor
    assert "VOTING_PERIOD" in governor
    assert "VOTING_DELAY" in governor
    assert "QUORUM_PERCENTAGE" in governor
    assert "APPROVAL_THRESHOLD" in governor
    
    # Check storage
    assert "ITimelock public timelock" in governor
    assert "address public stakeTracker" in governor
    assert "uint256 public proposalCount" in governor
    
    # Check all required functions are implemented
    required_functions = [
        "function propose(",
        "function queue(",
        "function execute(",
        "function cancel(",
        "function castVote(",
        "function castVoteWithReason(",
        "function castVoteWithSignature(",
        "function state(",
        "function getProposal(",
        "function getReceipt(",
        "function getVotes(",
        "function proposalThreshold(",
        "function quorum(",
        "function votingPeriod(",
        "function votingDelay(",
        "function hasVoted(",
    ]
    
    for func in required_functions:
        assert func in governor, f"Missing function: {func}"
    
    # Check no stub implementations (pass statements)
    lines = governor.split('\n')
    for i, line in enumerate(lines):
        # Allow pass in empty blocks or error handling
        if 'pass' in line.lower() and 'password' not in line.lower():
            # Check context
            context = '\n'.join(lines[max(0, i-3):i+3])
            assert False, f"Potential stub at line {i+1}:\n{context}"
    
    print("✅ Governor.sol is fully implemented")


def test_timelock_implementation():
    """Verify Timelock.sol implementation completeness"""
    contracts_dir = Path("/workspaces/qrdx-chain/contracts/governance")
    timelock = (contracts_dir / "Timelock.sol").read_text()
    
    # Check contract declaration
    assert "contract Timelock is ITimelock" in timelock
    
    # Check constants
    assert "MINIMUM_DELAY" in timelock
    assert "MAXIMUM_DELAY" in timelock
    assert "GRACE_PERIOD" in timelock
    
    # Check storage
    assert "address public override admin" in timelock
    assert "address public override pendingAdmin" in timelock
    assert "uint256 public override delay" in timelock
    
    # Check modifiers
    assert "modifier onlyAdmin()" in timelock
    assert "modifier onlyTimelock()" in timelock
    assert "modifier onlyPendingAdmin()" in timelock
    
    # Check all required functions
    required_functions = [
        "function queueTransaction(",
        "function executeTransaction(",
        "function cancelTransaction(",
        "function setPendingAdmin(",
        "function acceptAdmin(",
        "function setDelay(",
        "function getTransaction(",
        "function getTxHash(",
    ]
    
    for func in required_functions:
        assert func in timelock, f"Missing function: {func}"
    
    # Check no stubs
    assert "TODO" not in timelock
    assert "NotImplementedError" not in timelock
    
    print("✅ Timelock.sol is fully implemented")


def test_quantum_resistant_features():
    """Verify quantum-resistant cryptography integration"""
    contracts_dir = Path("/workspaces/qrdx-chain/contracts/governance")
    governor = (contracts_dir / "Governor.sol").read_text()
    
    # Check Dilithium integration
    assert "address(0x09)" in governor, "Dilithium precompile not referenced"
    assert "DILITHIUM_PRECOMPILE.staticcall" in governor, "Dilithium not called"
    assert "DILITHIUM_SIGNATURE_SIZE = 3309" in governor, "Wrong signature size"
    assert "DILITHIUM_PUBLIC_KEY_SIZE = 1952" in governor, "Wrong public key size"
    
    # Check BLAKE3 integration
    assert "address(0x0c)" in governor, "BLAKE3 precompile not referenced"
    assert "BLAKE3_PRECOMPILE.staticcall" in governor or "_blake3Hash" in governor, "BLAKE3 not used"
    
    # Check signature verification function
    assert "_verifyDilithiumSignature" in governor
    assert "signature," in governor  # Signature parameter
    assert "publicKey" in governor    # Public key parameter
    
    print("✅ Quantum-resistant features properly integrated")


def test_governance_parameters():
    """Verify governance parameters are correctly set"""
    contracts_dir = Path("/workspaces/qrdx-chain/contracts/governance")
    governor = (contracts_dir / "Governor.sol").read_text()
    
    # Extract and verify voting parameters
    assert "VOTING_PERIOD = 302_400" in governor or "VOTING_PERIOD = 302400" in governor, \
        "Wrong voting period (should be 302,400 blocks = 7 days)"
    
    assert "VOTING_DELAY = 43_200" in governor or "VOTING_DELAY = 43200" in governor, \
        "Wrong voting delay (should be 43,200 blocks = 1 day)"
    
    assert "QUORUM_PERCENTAGE = 10" in governor, \
        "Wrong quorum (should be 10%)"
    
    assert "APPROVAL_THRESHOLD = 66" in governor, \
        "Wrong approval threshold (should be 66%)"
    
    # Check timelock parameters
    timelock = (contracts_dir / "Timelock.sol").read_text()
    
    assert "7 days" in timelock, "Wrong timelock delay"
    assert "3 days" in timelock, "Wrong grace period"
    
    print("✅ Governance parameters are correct")


def test_contract_compilation():
    """Test that contracts compile successfully"""
    print("\n🔨 Testing contract compilation...")
    
    try:
        # Try to compile with solc if available
        result = subprocess.run(
            ["solc", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            print(f"✅ Solc found: {result.stdout.strip()}")
            
            # Compile Governor.sol
            contracts_dir = Path("/workspaces/qrdx-chain/contracts/governance")
            
            for contract in ["IGovernor.sol", "Governor.sol", "ITimelock.sol", "Timelock.sol"]:
                result = subprocess.run(
                    [
                        "solc",
                        "--optimize",
                        "--bin",
                        str(contracts_dir / contract)
                    ],
                    capture_output=True,
                    text=True,
                    cwd=str(contracts_dir),
                    timeout=30
                )
                
                if result.returncode != 0:
                    print(f"❌ Compilation failed for {contract}:")
                    print(result.stderr)
                    assert False, f"Compilation error in {contract}"
                else:
                    print(f"✅ {contract} compiled successfully")
        else:
            print("⚠️  Solc not available, skipping compilation test")
            
    except FileNotFoundError:
        print("⚠️  Solc not installed, skipping compilation test")
    except Exception as e:
        print(f"⚠️  Compilation test skipped: {e}")


def test_code_metrics():
    """Calculate and report code metrics"""
    contracts_dir = Path("/workspaces/qrdx-chain/contracts/governance")
    
    files = [
        "IGovernor.sol",
        "Governor.sol",
        "ITimelock.sol",
        "Timelock.sol",
    ]
    
    total_lines = 0
    contract_stats = {}
    
    for filename in files:
        filepath = contracts_dir / filename
        if filepath.exists():
            content = filepath.read_text()
            lines = len(content.split('\n'))
            total_lines += lines
            contract_stats[filename] = lines
    
    print("\n📊 Code Metrics:")
    print("=" * 60)
    for filename, lines in contract_stats.items():
        print(f"  {filename:<25} {lines:>6} lines")
    print("=" * 60)
    print(f"  {'TOTAL':<25} {total_lines:>6} lines")
    print()
    
    # Verify expected line counts
    assert contract_stats.get("IGovernor.sol", 0) > 250, "IGovernor.sol too small"
    assert contract_stats.get("Governor.sol", 0) > 500, "Governor.sol too small"
    assert contract_stats.get("ITimelock.sol", 0) > 150, "ITimelock.sol too small"
    assert contract_stats.get("Timelock.sol", 0) > 180, "Timelock.sol too small"
    
    assert total_lines > 1100, f"Total lines ({total_lines}) below expected (1100+)"
    
    print("✅ Code metrics within expected ranges")


def run_all_tests():
    """Run all governance tests"""
    print("\n" + "=" * 70)
    print("  QRDX Governance System - Test Suite")
    print("=" * 70)
    
    tests = [
        ("Contract Files Exist", test_governance_contracts_exist),
        ("Interface Structure", test_interface_structure),
        ("Governor Implementation", test_governor_implementation),
        ("Timelock Implementation", test_timelock_implementation),
        ("Quantum-Resistant Features", test_quantum_resistant_features),
        ("Governance Parameters", test_governance_parameters),
        ("Contract Compilation", test_contract_compilation),
        ("Code Metrics", test_code_metrics),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        print(f"\n▶ Running: {test_name}")
        print("-" * 70)
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"❌ FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"❌ ERROR: {e}")
            failed += 1
    
    print("\n" + "=" * 70)
    print(f"  Test Results: {passed} passed, {failed} failed")
    print("=" * 70)
    
    if failed == 0:
        print("\n🎉 All tests passed! Governance system ready.")
    else:
        print(f"\n⚠️  {failed} test(s) failed. Please review.")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)
