#!/bin/bash
set -e

# Navigate to project root
cd "$(dirname "$0")/.."

echo "=== Trustless Delegation System — End-to-End Verification ==="
echo ""

# Activate virtual environment
echo "→ Activating virtual environment..."
source .venv/bin/activate

# Compile contracts (downloads solc if needed)
echo "→ Ensuring Solidity compiler is available..."
python3 -c "from solcx import install_solc, set_solc_version; install_solc('0.8.24'); set_solc_version('0.8.24'); print('  solc 0.8.24 ready.')"

# Run tests
echo ""
echo "→ Running end-to-end test suite..."
echo "========================================"
python3 -m pytest tests/test_delegation.py -v --tb=short 2>/dev/null || python3 -m unittest tests.test_delegation -v
echo "========================================"
echo ""
echo "✓ All tests passed!"
