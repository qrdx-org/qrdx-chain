#!/usr/bin/env python3
"""Test validator component import and basic functionality."""

import sys
import traceback

try:
    print("Testing validator component import...")
    from trinity.components.builtin.qrpos_validator.component import QRPoSValidatorComponent
    print("✓ Import successful")
    
    # Try importing Address which was problematic before
    from eth.constants import ZERO_ADDRESS, EMPTY_UNCLE_HASH
    print("✓ Constants import successful")
    
    from eth.rlp.headers import BlockHeader
    print("✓ BlockHeader import successful")
    
    from eth.abc import BaseTransactionAPI
    print("✓ BaseTransactionAPI import successful")
    
    print("\n✅ All imports successful!")
    
except Exception as e:
    print(f"\n❌ Error: {type(e).__name__}: {e}")
    traceback.print_exc()
    sys.exit(1)
