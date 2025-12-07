# Objective: Phase 3 Production Readiness

## Goal
Fix all critical bugs and complete integration work to bring Phase 3 (QR-PoS Attestation System & Finality) to production standards.

## Acceptance Criteria
- [ ] Genesis timestamp properly set (slot calculation correct)
- [ ] Chain.consensus accessible for attestation pool queries
- [ ] Timestamp validation allows consecutive blocks
- [ ] Fork choice integrated with HeaderDB canonical chain selection
- [ ] Weight cache has bounded memory (LRU eviction)
- [ ] Attestations actually included in blocks (verified in logs)
- [ ] Testnet runs stably for 30+ minutes without crashes
- [ ] All unit tests pass (if any exist)
- [ ] No linting/type errors in modified code
- [ ] Documentation updated to reflect actual status

## Current Issues Found During Testing

### 1. Genesis Timestamp = 0 (CRITICAL)
**Symptom:** Block #10 claims to be for slot 333 instead of slot ~5
```
Wrong proposer for slot 333: expected validator 33, got 0
```
**Root Cause:** Genesis block timestamp = 0, causing `current_slot = (time.time() - 0) // 2` ≈ billions
**Impact:** Proposer selection wrong, blocks rejected, consensus breaks
**Fix Location:** Genesis import or slot calculation logic

### 2. Chain.consensus Attribute Missing (HIGH)
**Symptom:** 
```
WARNING: Failed to get attestations: 'CustomChain' object has no attribute 'consensus'
```
**Root Cause:** Chain object doesn't expose consensus engine
**Impact:** Blocks include 0 attestations instead of up to 128
**Fix Location:** Chain class or attestation retrieval code

### 3. Timestamp Validation Too Strict (MEDIUM)
**Symptom:**
```
ERROR: Header.timestamp 1765069706 is not greater than 1765069706
```
**Root Cause:** Blocks created in same second fail validation
**Impact:** Validators can't import their own blocks immediately
**Fix Location:** Byzantium header validation or QR-PoS override

### 4. Fork Choice Not Integrated (MEDIUM)
**Status:** ForkChoice class exists but never called
**Impact:** Attestation weights don't affect canonical chain selection
**Fix Location:** HeaderDB `_persist_header_chain()` method

### 5. Unbounded Weight Cache (LOW)
**Status:** `_block_weights` dict grows forever
**Impact:** Memory leak over time
**Fix Location:** FinalityGadget class

### 6. Daemon Task Return Bug (FIXED)
**Status:** ✅ Fixed lines 235 & 314 to use `continue` instead of `return`
**Impact:** Was causing Trinity crashes after 30 seconds

## Success Metrics
- Testnet runs for 30+ minutes continuously
- RPC responds on all 3 nodes
- Blocks produced every 2 seconds
- Logs show attestations being included
- No validation errors in logs
- Block numbers and slot numbers align properly

## Scope
**In Scope:**
- Critical bug fixes for existing Phase 3 code
- Integration of existing fork choice logic
- Basic memory management (cache eviction)
- Testnet validation

**Out of Scope:**
- New features (proposer boost, slashing, etc.)
- Comprehensive test suite (noted as future work)
- Performance optimization beyond basic fixes
- RPC endpoint additions
