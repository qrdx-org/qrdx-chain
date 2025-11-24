# QRDX Governance System

**Quantum-Resistant On-Chain Governance for QRDX Protocol**

## Overview

The QRDX Governance System enables decentralized control of the QRDX blockchain protocol through quantum-resistant voting and time-locked execution. Token holders with staked QRDX can create proposals, vote on changes, and execute approved modifications to protocol parameters.

### Key Features

- **Quantum-Resistant Voting**: Uses Dilithium (ML-DSA-65) signatures for post-quantum security
- **Time-Locked Execution**: 7-day delay prevents immediate execution of malicious proposals
- **Multi-Action Proposals**: Execute multiple contract calls in a single proposal
- **Flexible Integration**: Control QRDXChain, Bridge, AMM, and Treasury parameters
- **Transparent Process**: All actions recorded on-chain with full audit trail

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   QRDX Governance System                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐                                           │
│  │   Proposer   │                                           │
│  │  (1% stake)  │                                           │
│  └──────┬───────┘                                           │
│         │ Create                                            │
│         ▼                                                    │
│  ┌──────────────┐         ┌──────────────┐                 │
│  │   Governor   │────────▶│  Timelock    │                 │
│  │   Contract   │ Queue   │  (7-day)     │                 │
│  └──────────────┘         └──────┬───────┘                 │
│         │                        │                           │
│         │ Vote (7 days)          │ Execute                   │
│         ▼                        ▼                           │
│  ┌──────────────┐         ┌─────────────────────────┐      │
│  │    Voters    │         │  GovernanceIntegration  │      │
│  │ (Dilithium)  │         └──────────┬──────────────┘      │
│  └──────────────┘                    │                      │
│                                      │                       │
│                                      ▼                       │
│  ┌───────────────────────────────────────────────────┐     │
│  │           Protocol Components                      │     │
│  ├───────────────────────────────────────────────────┤     │
│  │  • QRDXChain (parameters, consensus)              │     │
│  │  • Bridge (thresholds, fees, validators)          │     │
│  │  • AMM (fee tiers, hooks, protocol fee)           │     │
│  │  • Treasury (distribution, grants, rewards)       │     │
│  └───────────────────────────────────────────────────┘     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Contracts

### Governor.sol
Main governance contract managing proposals and voting.

**Key Parameters**:
- Voting Period: 7 days (302,400 blocks @ 2s/block)
- Voting Delay: 1 day (43,200 blocks)
- Quorum: 10% of total staked QRDX
- Approval Threshold: 66% of votes cast
- Proposal Threshold: 1% of total staked QRDX

### Timelock.sol
Time-locked execution contract for security.

**Key Parameters**:
- Minimum Delay: 7 days
- Maximum Delay: 30 days
- Grace Period: 3 days (execution window)

### GovernanceIntegration.sol
Integration layer connecting governance to protocol components.

**Manages**:
- QRDXChain protocol parameters
- Bridge validator settings and fees
- AMM fee tiers and hooks
- Treasury distributions and grants

## Governance Process

### 1. Proposal Creation

**Requirements**:
- Minimum 1% of total staked QRDX (~15,000 QRDX if 1.5M staked)
- Valid proposal title and description
- At least one executable action
- Maximum 10 actions per proposal

**Example**:
```solidity
address[] memory targets = new address[](1);
targets[0] = address(governanceIntegration);

uint256[] memory values = new uint256[](1);
values[0] = 0;

bytes[] memory calldatas = new bytes[](1);
calldatas[0] = abi.encodeWithSignature(
    "setBridgeFeeRate(uint256)",
    20  // 0.2% fee
);

uint256 proposalId = governor.propose(
    targets,
    values,
    calldatas,
    "Reduce Bridge Fee",
    "Lower bridge fee from 0.3% to 0.2% to increase usage"
);
```

### 2. Voting Period (7 days)

After a 1-day delay, voting begins and lasts for 7 days.

**Voting Options**:
- **For**: Support the proposal
- **Against**: Oppose the proposal
- **Abstain**: Count toward quorum but neither for nor against

**Standard Vote**:
```solidity
governor.castVote(proposalId, 1);  // 1 = For
```

**Vote with Reason**:
```solidity
governor.castVoteWithReason(
    proposalId,
    1,
    "Lower fees will attract more users to the bridge"
);
```

**Quantum-Resistant Vote with Signature**:
```solidity
// Offline: Generate Dilithium signature
bytes memory message = abi.encodePacked("vote", proposalId, support, chainId);
bytes memory signature = dilithiumSigner.sign(message);

// Online: Submit vote
governor.castVoteWithSignature(
    proposalId,
    1,  // For
    signature,
    dilithiumPublicKey
);
```

### 3. Queuing (after voting ends)

If the proposal succeeds (meets quorum and threshold), it can be queued.

**Requirements**:
- Quorum met: Total votes ≥ 10% of staked QRDX
- Threshold met: For votes ≥ 66% of (For + Against)

```solidity
governor.queue(proposalId);
```

### 4. Execution (after 7-day delay)

Once the timelock delay passes, the proposal can be executed.

**Execution Window**: 3 days after delay expires

```solidity
governor.execute(proposalId);
```

## Proposal States

Proposals progress through the following states:

1. **Pending**: Proposal created, voting not yet started (1-day delay)
2. **Active**: Voting period active (7 days)
3. **Canceled**: Proposal canceled by proposer
4. **Defeated**: Failed to meet quorum or threshold
5. **Succeeded**: Passed, ready to queue
6. **Queued**: Waiting for timelock delay
7. **Expired**: Not executed within grace period
8. **Executed**: Successfully executed

## Voting Power

Voting power is determined by staked QRDX balance at the block when the proposal was created (snapshot).

**Calculation**:
```solidity
uint256 votes = stakeTracker.getStake(voter, proposal.startBlock);
```

This prevents:
- Vote buying (can't stake after proposal creation)
- Flash loan attacks
- Double voting

## Security Features

### Time Lock
- **7-day delay** between approval and execution
- Allows community to review and exit if needed
- Prevents immediate execution of malicious proposals

### Signature Replay Protection
- Each Dilithium signature can only be used once
- Signatures include chain ID to prevent cross-chain replay
- Nonce tracking prevents reuse

### Proposal Threshold
- Requires 1% of staked QRDX to propose
- Prevents spam proposals
- Ensures proposer has skin in the game

### Emergency Cancellation
- Admin (Governor) can cancel queued transactions
- Proposer can cancel their own proposal
- Automatic cancellation if proposer's stake drops below threshold

## Example Proposals

### Example 1: Update Bridge Fee

```solidity
function proposeBridgeFeeUpdate() external returns (uint256) {
    address[] memory targets = new address[](1);
    targets[0] = address(governanceIntegration);
    
    uint256[] memory values = new uint256[](1);
    values[0] = 0;
    
    bytes[] memory calldatas = new bytes[](1);
    calldatas[0] = abi.encodeWithSignature(
        "setBridgeFeeRate(uint256)",
        15  // 0.15% fee
    );
    
    return governor.propose(
        targets,
        values,
        calldatas,
        "QIP-001: Reduce Bridge Fee to 0.15%",
        "## Summary\n\nReduce bridge fee from 0.3% to 0.15%\n\n## Motivation\n\nLower fees will increase bridge usage and TVL\n\n## Specification\n\nCall setBridgeFeeRate(15) on GovernanceIntegration"
    );
}
```

### Example 2: Treasury Grant

```solidity
function proposeDevGrant() external returns (uint256) {
    address[] memory targets = new address[](1);
    targets[0] = address(governanceIntegration);
    
    uint256[] memory values = new uint256[](1);
    values[0] = 0;
    
    bytes[] memory calldatas = new bytes[](1);
    calldatas[0] = abi.encodeWithSignature(
        "fundGrant(address,uint256,uint256,string)",
        0x1234567890123456789012345678901234567890,
        100_000 ether,  // 100,000 QRDX
        90 days,        // 3-month vesting
        "Core Protocol Development Q1 2026"
    );
    
    return governor.propose(
        targets,
        values,
        calldatas,
        "QIP-002: Fund Core Development Team",
        "## Summary\n\nAllocate 100,000 QRDX to core dev team\n\n## Team\n\n- Lead: Alice (github.com/alice)\n- Scope: Consensus improvements, MEV protection\n\n## Deliverables\n\n1. Implement MEV-resistant block building\n2. Optimize validator selection\n3. Reduce finality time to 1 second"
    );
}
```

### Example 3: Multi-Action Proposal

```solidity
function proposeComprehensiveUpdate() external returns (uint256) {
    address[] memory targets = new address[](3);
    targets[0] = address(governanceIntegration);
    targets[1] = address(governanceIntegration);
    targets[2] = address(governanceIntegration);
    
    uint256[] memory values = new uint256[](3);
    values[0] = 0;
    values[1] = 0;
    values[2] = 0;
    
    bytes[] memory calldatas = new bytes[](3);
    
    // Action 1: Update bridge fee
    calldatas[0] = abi.encodeWithSignature(
        "setBridgeFeeRate(uint256)",
        20
    );
    
    // Action 2: Update AMM protocol fee
    calldatas[1] = abi.encodeWithSignature(
        "setAMMProtocolFee(uint24,uint16)",
        500,   // 0.05% fee tier
        100    // 1% protocol fee
    );
    
    // Action 3: Update fee distribution
    calldatas[2] = abi.encodeWithSignature(
        "setFeeDistribution(uint256,uint256,uint256)",
        6000,  // 60% to validators
        3000,  // 30% to treasury
        1000   // 10% burn
    );
    
    return governor.propose(
        targets,
        values,
        calldatas,
        "QIP-003: Q1 2026 Protocol Parameter Update",
        "## Summary\n\nComprehensive update of protocol fees and distribution\n\n## Changes\n\n1. Bridge fee: 0.3% → 0.2%\n2. AMM protocol fee: 0% → 1%\n3. Fee distribution: More to treasury for development\n\n## Rationale\n\nBalance revenue generation with user adoption"
    );
}
```

## Governance Parameters Reference

### Governor Contract

| Parameter | Value | Purpose |
|-----------|-------|---------|
| Voting Period | 302,400 blocks (7 days) | Time for community to vote |
| Voting Delay | 43,200 blocks (1 day) | Prevents surprise proposals |
| Quorum | 10% of staked QRDX | Minimum participation |
| Approval Threshold | 66% | Supermajority for changes |
| Proposal Threshold | 1% of staked QRDX | Spam prevention |

### Timelock Contract

| Parameter | Value | Purpose |
|-----------|-------|---------|
| Minimum Delay | 7 days | Security buffer |
| Maximum Delay | 30 days | Reasonable upper bound |
| Grace Period | 3 days | Execution window |

### Integration Parameters

#### QRDXChain
- Block Gas Limit: 10M - 100M gas
- Base Fee Target: 0-100% utilization
- Validator Set Size: 100-500 validators
- Min Validator Stake: 10,000 - 1,000,000 QRDX

#### Bridge
- Confirmation Threshold: 51-90%
- Challenge Period: 3-14 days
- Fee Rate: 0-1% (0-100 basis points)

#### AMM
- Protocol Fee: 0-10% (0-1000 basis points)
- Fee Tiers: Custom configurations
- Hook Approvals: Whitelist management

#### Treasury
- Fee Distribution: Customizable percentages
- Grant Funding: With optional vesting
- Arbitrary Calls: Emergency governance actions

## Gas Costs

Estimated gas usage for governance operations:

| Operation | Gas Cost | Notes |
|-----------|----------|-------|
| Create Proposal | ~250,000 | Varies with action count |
| Cast Vote | ~80,000 | Standard voting |
| Cast Vote (Signature) | ~150,000 | Includes Dilithium verification |
| Queue Proposal | ~100,000 per action | Multiple timelock calls |
| Execute Proposal | Variable | Depends on actions executed |
| Cancel Proposal | ~50,000 | Simple state update |

## Security Considerations

### For Proposers

1. **Test Actions First**: Verify all actions work on testnet
2. **Clear Description**: Explain rationale and expected impact
3. **Monitor Voting**: Watch for concerns or objections
4. **Be Available**: Answer questions during voting period

### For Voters

1. **Research Proposals**: Read description and code
2. **Understand Impact**: Know what will change
3. **Vote Your Interest**: Don't delegate decisions blindly
4. **Monitor Execution**: Ensure proposal executes as intended

### For Protocol

1. **Time Lock**: 7-day delay allows exit before harmful changes
2. **Supermajority**: 66% threshold prevents contentious changes
3. **Quorum**: 10% ensures legitimacy
4. **Quantum-Resistant**: Dilithium protects against quantum attacks
5. **Audit Trail**: All actions on-chain and verifiable

## Common Issues

### "Insufficient voting power to propose"
**Cause**: Your staked QRDX is below 1% of total stake  
**Solution**: Acquire more QRDX and stake it, or find others to co-propose

### "Proposal not succeeded"
**Causes**:
- Quorum not met (< 10% participation)
- Threshold not met (< 66% approval)  
**Solution**: Build more community support before proposing

### "Transaction expired"
**Cause**: Didn't execute within 3-day grace period  
**Solution**: Re-queue the proposal or create a new one

### "Transaction not yet executable"
**Cause**: 7-day timelock delay hasn't passed  
**Solution**: Wait until block.timestamp ≥ eta

## Deployment Guide

### 1. Deploy Contracts

```solidity
// Deploy Timelock (7-day delay)
Timelock timelock = new Timelock(
    address(0),  // Temporary admin
    7 days
);

// Deploy Governor
Governor governor = new Governor(
    "QRDX Governor",
    address(timelock),
    address(stakeTracker)
);

// Deploy GovernanceIntegration
GovernanceIntegration integration = new GovernanceIntegration(
    address(timelock),
    address(qrdxChain),
    address(bridgeEth),
    address(bridgeQRDX),
    address(poolManager),
    address(treasury)
);

// Set Governor as Timelock admin
timelock.setPendingAdmin(address(governor));
// Governor accepts admin role via proposal
```

### 2. Initialize Parameters

```solidity
// Verify voting parameters
assert(governor.votingPeriod() == 302_400);
assert(governor.votingDelay() == 43_200);
assert(governor.proposalThreshold() > 0);

// Verify timelock
assert(timelock.delay() == 7 days);
assert(timelock.gracePeriod() == 3 days);
```

### 3. Create Initial Proposal

```solidity
// First proposal: Accept admin role
address[] memory targets = new address[](1);
targets[0] = address(timelock);

bytes[] memory calldatas = new bytes[](1);
calldatas[0] = abi.encodeWithSignature("acceptAdmin()");

uint256 proposalId = governor.propose(
    targets,
    new uint256[](1),
    calldatas,
    "Initialize Governance",
    "Transfer timelock admin to Governor"
);
```

## Testing

Run the governance test suite:

```bash
cd /workspaces/qrdx-chain
python scripts/test_governance.py
```

Expected output:
```
✅ All governance contract files exist
✅ IGovernor.sol has correct structure
✅ ITimelock.sol has correct structure
✅ Governor.sol is fully implemented
✅ Timelock.sol is fully implemented
✅ Quantum-resistant features properly integrated
✅ Governance parameters are correct
✅ Code metrics within expected ranges

🎉 All tests passed! Governance system ready.
```

## Further Reading

- [QRDX Whitepaper v2.0](../docs/QRDX-Whitepaper-v2.0.md)
- [QR-PoS Consensus](../py-evm/eth/consensus/qr_pos.py)
- [Dilithium Integration](../py-evm/eth/crypto/dilithium.py)
- [Bridge Documentation](../contracts/bridge/README.md)
- [AMM Documentation](../contracts/qrdx-amm/)

## Support

- **GitHub**: [github.com/qrdx-org/qrdx-chain](https://github.com/qrdx-org/qrdx-chain)
- **Discord**: [discord.gg/qrdx](https://discord.gg/qrdx)
- **Forum**: [forum.qrdx.org](https://forum.qrdx.org)

## License

MIT License - See [LICENSE](../../LICENSE) for details
