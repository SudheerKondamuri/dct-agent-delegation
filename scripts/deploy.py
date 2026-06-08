"""
Deployment script for DCT Agent Delegation contracts.

Deploys to any EVM network (Base Sepolia, local Anvil, etc.).
Usage:
  python scripts/deploy.py --rpc <RPC_URL> --private-key <PRIVATE_KEY>
  python scripts/deploy.py --network base-sepolia  # reads .env
"""

import os
import sys
import json
import argparse
import subprocess

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from web3 import Web3
from solcx import compile_standard, install_solc, set_solc_version

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONTRACTS_DIR = os.path.join(PROJECT_ROOT, "contracts")

ENTRY_POINT_ADDRESS = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"


def load_env():
    env_path = os.path.join(PROJECT_ROOT, ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip("\"'")
            if key not in os.environ:
                os.environ[key] = value


def read_sol(name):
    path = os.path.join(CONTRACTS_DIR, f"{name}.sol")
    with open(path) as f:
        return f.read()


def compile_contracts():
    try:
        set_solc_version("0.8.24")
    except Exception:
        install_solc("0.8.24")
        set_solc_version("0.8.24")

    sources = {}
    for fname in os.listdir(CONTRACTS_DIR):
        if fname.endswith(".sol"):
            sources[fname] = {"content": read_sol(fname.replace(".sol", ""))}

    compiled = compile_standard(
        {
            "language": "Solidity",
            "sources": sources,
            "settings": {
                "optimizer": {"enabled": True, "runs": 200},
                "outputSelection": {
                    "*": {
                        "*": ["abi", "evm.bytecode.object"],
                    }
                },
            },
        },
        allow_paths=CONTRACTS_DIR,
    )

    artifacts = {}
    for source_name, contracts in compiled["contracts"].items():
        for contract_name, info in contracts.items():
            artifacts[contract_name] = {
                "abi": info["abi"],
                "bytecode": "0x" + info["evm"]["bytecode"]["object"],
            }
    return artifacts


def deploy_contract(w3, artifact, *args, from_addr=None, private_key=None):
    contract = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])
    tx = contract.constructor(*args).build_transaction({
        "from": from_addr,
        "nonce": w3.eth.get_transaction_count(from_addr),
        "gas": 3000000,
        "gasPrice": w3.eth.gas_price,
    })
    signed = w3.eth.account.sign_transaction(tx, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return w3.eth.contract(address=receipt["contractAddress"], abi=artifact["abi"])


def send_tx(w3, contract, func_name, args, from_addr=None, private_key=None):
    tx = contract.functions[func_name](*args).build_transaction({
        "from": from_addr,
        "nonce": w3.eth.get_transaction_count(from_addr),
        "gas": 200000,
        "gasPrice": w3.eth.gas_price,
    })
    signed = w3.eth.account.sign_transaction(tx, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    return w3.eth.wait_for_transaction_receipt(tx_hash)


def main():
    parser = argparse.ArgumentParser(description="Deploy DCT contracts")
    parser.add_argument("--rpc", help="RPC URL")
    parser.add_argument("--private-key", help="Deployer private key")
    parser.add_argument("--network", choices=["base-sepolia", "hardhat", "anvil"],
                        default="anvil", help="Named network (reads .env for base-sepolia)")
    args = parser.parse_args()

    load_env()

    if args.network == "base-sepolia":
        rpc = args.rpc or os.environ.get("BASE_SEPOLIA_RPC_URL", "https://sepolia.base.org")
        pk = args.private_key or os.environ.get("DEPLOYER_PRIVATE_KEY")
        if not pk:
            print("ERROR: DEPLOYER_PRIVATE_KEY not set in .env or --private-key")
            sys.exit(1)
    elif args.network in ("hardhat", "anvil"):
        rpc = args.rpc or "http://127.0.0.1:8545"
        pk = args.private_key
        if not pk:
            print("WARNING: No private key provided; using first anvil account")
            # test mnemonic: test test test test test test test test test test test junk
            from eth_account import Account
            Account.enable_unaudited_hdwallet_features()
            acct = Account.from_mnemonic(
                "test test test test test test test test test test test junk",
                account_path="m/44'/60'/0'/0/0"
            )
            pk = acct.key.hex()
    else:
        rpc = args.rpc or "http://127.0.0.1:8545"
        pk = args.private_key

    w3 = Web3(Web3.HTTPProvider(rpc))
    if not w3.is_connected():
        print(f"ERROR: Cannot connect to {rpc}")
        sys.exit(1)

    deployer = w3.eth.account.from_key(pk)
    deployer_addr = deployer.address
    print(f"Deployer: {deployer_addr}")
    print(f"Network:  {rpc}")
    print(f"Balance:  {w3.from_wei(w3.eth.get_balance(deployer_addr), 'ether')} ETH\n")

    print("Compiling contracts...")
    artifacts = compile_contracts()
    print(f"  Compiled: {', '.join(artifacts.keys())}\n")

    # 1. LineageRegistry
    print("--- Deploying LineageRegistry ---")
    registry = deploy_contract(w3, artifacts["LineageRegistry"],
                               from_addr=deployer_addr, private_key=pk)
    print(f"  LineageRegistry: {registry.address}")

    # 2. TrustScorer
    print("\n--- Deploying TrustScorer ---")
    scorer = deploy_contract(w3, artifacts["TrustScorer"],
                             from_addr=deployer_addr, private_key=pk)
    print(f"  TrustScorer: {scorer.address}")

    # 3. EnforcementLayer
    print("\n--- Deploying EnforcementLayer ---")
    enforcer = deploy_contract(w3, artifacts["EnforcementLayer"],
                               registry.address, scorer.address,
                               from_addr=deployer_addr, private_key=pk)
    print(f"  EnforcementLayer: {enforcer.address}")

    # 4. Wire enforcer into TrustScorer
    print("\n--- Wiring enforcer into TrustScorer ---")
    send_tx(w3, scorer, "setEnforcer", [enforcer.address],
            from_addr=deployer_addr, private_key=pk)
    print(f"  TrustScorer.enforcer = {enforcer.address}")

    # 5. TargetContract (demo)
    print("\n--- Deploying TargetContract ---")
    target = deploy_contract(w3, artifacts["TargetContract"],
                             from_addr=deployer_addr, private_key=pk)
    print(f"  TargetContract: {target.address}")

    # 6. AgentAccount (ERC-4337)
    print("\n--- Deploying AgentAccount ---")
    account = deploy_contract(w3, artifacts["AgentAccount"],
                              ENTRY_POINT_ADDRESS, enforcer.address,
                              from_addr=deployer_addr, private_key=pk)
    print(f"  AgentAccount: {account.address}")

    print("\n=== Deployment Summary ===")
    print(f"LineageRegistry:    {registry.address}")
    print(f"TrustScorer:        {scorer.address}")
    print(f"EnforcementLayer:   {enforcer.address}")
    print(f"TargetContract:     {target.address}")
    print(f"AgentAccount:       {account.address}")
    print(f"EntryPoint (fixed): {ENTRY_POINT_ADDRESS}")


if __name__ == "__main__":
    main()
