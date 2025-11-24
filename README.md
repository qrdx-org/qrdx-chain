# QRDX Chain - Quantum-Resistant Blockchain

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

**QRDX Chain** is the world's first quantum-resistant blockchain implementing post-quantum cryptographic primitives (CRYSTALS-Dilithium, CRYSTALS-Kyber) with native asset shielding and concentrated liquidity AMM capabilities.

## 🌟 Key Features

- **Post-Quantum Security**: NIST-standardized CRYSTALS-Dilithium signatures and CRYSTALS-Kyber key encapsulation
- **Quantum-Resistant Proof-of-Stake (QR-PoS)**: 150 validators, 2-second block time, single-slot finality
- **QEVM**: Quantum-resistant Ethereum Virtual Machine with PQ precompiles
- **Asset Shielding**: Convert ETH, BTC, and ERC-20 tokens to quantum-resistant equivalents (qETH, qBTC, etc.)
- **QRDX Protocol AMM**: Concentrated liquidity DEX based on Uniswap v3/v4 architecture
- **5,000+ TPS**: High-performance blockchain designed for DeFi
- **On-Chain Governance**: Community-driven protocol evolution

## 📖 Documentation

Full documentation is available in the [docs/](docs/) directory:
- [Whitepaper v2.0](docs/QRDX-Whitepaper-v2.0.md)
- [Architecture Guide](docs/guides/)
- [API Reference](docs/api/)

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip and virtualenv
- 8GB+ RAM recommended
- Linux, macOS, or Windows with WSL2

### Installation

```bash
# Clone the repository
git clone https://github.com/qrdx-org/qrdx-chain.git
cd qrdx-chain

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -e .

# Run tests
pytest tests/
```

### Running a Node

```bash
# Start a QRDX Chain node
qrdx-chain --network-id=1 --data-dir=~/.qrdx

# Become a validator (requires 100,000 QRDX staked)
qrdx-chain validator --stake-amount=100000
```

## 🏗️ Architecture

QRDX Chain is built on a modified py-evm/Trinity codebase with the following components:

```
├── py-evm/              # QEVM - Quantum-resistant EVM
│   ├── eth/crypto/      # Post-quantum cryptography (Dilithium, Kyber, BLAKE3)
│   ├── eth/consensus/   # QR-PoS consensus mechanism
│   └── eth/vm/          # Virtual machine with PQ precompiles
├── trinity/             # Client implementation
├── contracts/           # Smart contracts (AMM, Bridge, Governance)
└── tests/               # Comprehensive test suite
```

## 🔐 Post-Quantum Cryptography

QRDX Chain implements NIST-standardized post-quantum algorithms:

| Algorithm | Purpose | Security Level |
|-----------|---------|----------------|
| CRYSTALS-Dilithium | Digital signatures | NIST Level 3 |
| CRYSTALS-Kyber | Key encapsulation | NIST Level 3 |
| BLAKE3 | Hashing | 256-bit quantum resistance |

## 🧪 Development Status

**Current Version**: 1.0.0-alpha.1  
**Status**: Active Development

- [x] Post-quantum cryptography integration
- [x] Project structure and dependencies
- [ ] QR-PoS consensus implementation
- [ ] QEVM with PQ precompiles
- [ ] qRC20 token standard
- [ ] QRDX Protocol AMM
- [ ] Asset shielding bridge
- [ ] Governance system

See [DEVELOPMENT.md](DEVELOPMENT.md) for detailed progress and contribution guidelines.

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install

# Run tests
pytest tests/ -v

# Run type checking
mypy py-evm/eth trinity/
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- Website: https://qrdx.org
- Documentation: https://docs.qrdx.org
- Discord: https://discord.gg/qrdx
- Twitter: https://twitter.com/qrdx_official
- GitHub: https://github.com/qrdx-org

## ⚠️ Disclaimer

QRDX Chain is experimental software under active development. Use at your own risk. The protocol has not yet undergone full security audits. See [SECURITY.md](SECURITY.md) for more information.

## 🙏 Acknowledgments

Built on the foundation of:
- Trinity (Ethereum client)
- py-evm (Ethereum Virtual Machine)
- Open Quantum Safe (liboqs)
- Uniswap v3/v4 (AMM architecture)

---

**For the latest updates, visit [qrdx.org](https://qrdx.org)**
