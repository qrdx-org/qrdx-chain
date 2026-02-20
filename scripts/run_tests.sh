#!/bin/bash
# Run tests for QRDX chain
cd ..
python -m pytest tests/ --ignore=tests/test_block_explorer_api.py -v --tb=short