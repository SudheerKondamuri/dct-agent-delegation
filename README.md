# DCT Agent Delegation — Trustless Delegation System for Autonomous AI Agents

## Overview

An end-to-end trustless delegation system for autonomous multi-agent AI systems. Integrates off-chain cryptographic primitives (Eclipse Biscuit-style tokens) with on-chain smart contracts on EVM-compatible blockchains.

## Architecture

The system is composed of five layers that execute in sequence for every agent action:

1. **Off-chain Token Layer** — Eclipse Biscuit / Ed25519 (attenuate + delegate)
2. **On-chain Lineage Registry** — Solidity / Base Sepolia (register lineage)
3. **Enforcement Layer** — ERC-7710 / ERC-4337 (enforce at execution)
4. **TLSNotary Attestation** — MPC over TLS (verify action proof)
5. **Trust Scoring** — On-chain reputation (update score)

## Contract Addresses (Base Sepolia)

| Contract | Address |
|----------|---------|
| LineageRegistry | `DEPLOYED_ADDRESS` |
| TrustScorer | `DEPLOYED_ADDRESS` |
| EnforcementLayer | `DEPLOYED_ADDRESS` |
| TargetContract (demo) | `DEPLOYED_ADDRESS` |
| AgentAccount (ERC-4337) | `DEPLOYED_ADDRESS` |
| EntryPoint (canonical) | `0x0000000071727De22E5E9d8BAf0edAc6f37da032` |

## Core Components

### Off-chain Token Layer (`client.py`)

- **`mint_root_token`** — Mints a root Biscuit-like token with Ed25519 signatures, encoding agent identity, scopes, depth, and TTL
- **`attenuate_token`** — Appends a signed block narrowing scope; enforces depth ceiling
- **`verify_token`** — Verifies token offline using only the root public key; checks signature chain, expiry, depth, and scope
- **`generate_child_keypair`** — Generates ephemeral Ed25519 keypair per delegation hop

### On-chain Lineage Registry (`contracts/LineageRegistry.sol`)

- **`register`** — Records agent-parent relationship; enforces MAX_DEPTH = 8
- **`revoke`** — Marks an agent revoked; caller must be agent or direct parent
- **`isActive`** — Walks lineage up to MAX_DEPTH; O(8) bounded gas cost
- **`commitProofHash`** — Commits TLSNotary proof hash for on-chain verification

### Enforcement Layer (`contracts/EnforcementLayer.sol`)

Implements ERC-7710 `IDelegationManager` with 4 sequential checks:

1. Lineage validity (`registry.isActive`)
2. Token signature verification (ECDSA)
3. Scope validation (function selector check)
4. TLSNotary attestation (proof hash verification)

### Trust Scorer (`contracts/TrustScorer.sol`)

- **`onSuccess`** — Logarithmic score growth
- **`onViolation`** — Flat slashing (500/1000)
- **`maxDelegationDepth`** — Score-tiered depth limits (1/3/5/8)

### ERC-4337 Integration (`contracts/AgentAccount.sol`)

- `validateUserOp` calls `enforcer.validateDelegation()` during validation phase
- `execute` calls `enforcer.redeemDelegation()` during execution phase
- Delegation data passed via UserOperation signature field

## Project Structure

```
contracts/
├── AgentAccount.sol      # ERC-4337 account integrating EnforcementLayer
├── EnforcementLayer.sol   # ERC-7710 delegation manager with 4-check pipeline
├── LineageRegistry.sol    # On-chain delegation lineage with cascade revocation
├── TargetContract.sol     # Demo target (read/write functions)
└── TrustScorer.sol        # On-chain reputation with score tiers

scripts/
└── deploy.js              # Hardhat deployment script (Base Sepolia)

tests/
├── test_delegation.py     # End-to-end test suite
└── verify.sh              # Verification runner

client.py                  # Off-chain Python client (token layer + TLSNotary)
```

## Setup

### Prerequisites

- Python 3.14+
- Node.js 20+
- Anvil (for local testing): `curl -L https://foundry.paradigm.xyz | bash && foundryup`
- Solc 0.8.24 (auto-installed by tests)

### Installation

```bash
# Python dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install requests web3 eth-account eth-hash py-solc-x cryptography

# Copy env template
cp .env.example .env
# Edit .env with your private key and RPC URL
```

### Run Tests (Local Anvil)

```bash
source .venv/bin/activate
bash tests/verify.sh
```

### Deploy to Base Sepolia

```bash
# Requires .env with funded wallet
source .venv/bin/activate
python scripts/deploy.py --network base-sepolia
```

After deployment, update contract addresses in this README.

### Deploy to Local Anvil (For Testing)

```bash
# Start anvil first
anvil &

# Deploy
source .venv/bin/activate
python scripts/deploy.py --network anvil
```

## Verification

The test suite covers:

1. Off-chain token lifecycle (mint → attenuate → verify)
2. On-chain registry + cascade revocation
3. TLSNotary attestation + proof commitment
4. Enforcement pipeline + trust scoring
5. ERC-4337 integration (AgentAccount validation flow)
