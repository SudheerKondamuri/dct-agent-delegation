"""
End-to-end test suite for the Trustless Delegation System.

Covers:
  1. Off-chain Biscuit-like token lifecycle (mint → attenuate → verify)
  2. On-chain LineageRegistry (register → depth → cascade revoke)
  3. TLSNotary attestation and on-chain proof commitment
  4. Sequential enforcement pipeline (EnforcementLayer) and reputation scoring
  5. ERC-4337 integration (AgentAccount + MockEntryPoint)
"""

import os
import sys
import time
import json
import subprocess
import unittest
import hashlib

from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_hash.auto import keccak
from solcx import compile_standard, install_solc, set_solc_version

# Add workspace root to path
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from client import (
    generate_child_keypair,
    mint_root_token,
    attenuate_token,
    verify_token,
    init_tlsnotary_session,
    execute_notarized_request,
    commit_proof_hash,
    calculate_proof_hash,
    _extract_next_keypair,
    KeyPair,
    PublicKey,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONTRACTS_DIR = os.path.join(PROJECT_ROOT, "contracts")


def _read_sol(name: str) -> str:
    path = os.path.join(CONTRACTS_DIR, f"{name}.sol")
    with open(path, "r") as f:
        return f.read()


def _compile_contracts():
    """Compile all Solidity contracts using py-solc-x and return ABI+bytecode."""
    try:
        set_solc_version("0.8.24")
    except Exception:
        install_solc("0.8.24")
        set_solc_version("0.8.24")

    sources = {}
    for fname in os.listdir(CONTRACTS_DIR):
        if fname.endswith(".sol"):
            sources[fname] = {"content": _read_sol(fname.replace(".sol", ""))}

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


def _token_hash(token_b64: str) -> bytes:
    """Compute keccak256 hash of the Biscuit token string for on-chain reference."""
    return keccak(token_b64.encode("utf-8"))


def _sign_delegation(account: Account, token_hash: bytes, proof_hash: bytes) -> tuple:
    """
    Sign a delegation digest with the agent's Ethereum private key.
    Returns (v, r, s) for ECDSA recovery.
    """
    from eth_account._utils.signing import sign_message_hash, PrivateKey
    digest = keccak(token_hash + proof_hash)
    key = PrivateKey(account.key)
    v, r, s, _ = sign_message_hash(key, digest)
    return v, r, s


# ---------------------------------------------------------------------------
# Test suite
# ---------------------------------------------------------------------------


class TestDelegationSystem(unittest.TestCase):
    """Full end-to-end tests for the DCT agent delegation system."""

    anvil_process = None
    w3 = None
    accounts = None
    artifacts = None

    @classmethod
    def setUpClass(cls):
        # 1. Connect to (or start) a local Anvil node
        cls.w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
        if not cls.w3.is_connected():
            print("Starting local Anvil node...")
            cls.anvil_process = subprocess.Popen(
                ["anvil"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            for _ in range(30):
                time.sleep(1)
                if cls.w3.is_connected():
                    break
            if not cls.w3.is_connected():
                raise RuntimeError("Failed to start Anvil node")
        else:
            print("Connected to existing Anvil node.")

        cls.accounts = cls.w3.eth.accounts

        # 2. Compile Solidity contracts
        print("Compiling Solidity contracts...")
        cls.artifacts = _compile_contracts()
        print(f"Compiled contracts: {list(cls.artifacts.keys())}")

    @classmethod
    def tearDownClass(cls):
        if cls.anvil_process:
            print("Terminating Anvil node...")
            cls.anvil_process.terminate()
            cls.anvil_process.wait()

    # -- deployment helper ---------------------------------------------------

    def deploy(self, name: str, *args):
        """Deploy a contract by name and return a web3 Contract instance."""
        art = self.artifacts[name]
        contract = self.w3.eth.contract(abi=art["abi"], bytecode=art["bytecode"])
        tx_hash = contract.constructor(*args).transact({"from": self.accounts[0]})
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        return self.w3.eth.contract(address=receipt.contractAddress, abi=art["abi"])

    # ========================================================================
    # Test 01 — Off-chain token lifecycle
    # ========================================================================

    def test_01_offchain_token_layer(self):
        print("\n--- Test 01: Off-Chain Biscuit-like Token Layer ---")

        root_kp = KeyPair.generate()
        scopes = ["read", "write"]
        max_depth = 3
        ttl = 3600

        # ---- Mint root token ------------------------------------------------
        root_token = mint_root_token(
            issuer_keypair=root_kp,
            agent_id="orchestrator",
            allowed_scopes=scopes,
            max_depth=max_depth,
            ttl_seconds=ttl,
        )
        self.assertIsNotNone(root_token)
        print("  ✓ Root token minted.")

        # ---- Verify root token -----------------------------------------------
        self.assertTrue(verify_token(root_token, root_kp.public_key, "files", "read"))
        self.assertTrue(verify_token(root_token, root_kp.public_key, "files", "write"))
        self.assertFalse(verify_token(root_token, root_kp.public_key, "files", "admin"))
        print("  ✓ Root token verification correct.")

        # ---- Attenuate to child (read only) ----------------------------------
        child_kp = generate_child_keypair()
        child_token = attenuate_token(
            parent_token_b64=root_token,
            parent_keypair=root_kp,
            child_agent_id=child_kp.public_key.to_bytes().hex(),
            narrowed_scopes=["read"],
            ttl_seconds=600,
        )
        self.assertIsNotNone(child_token)
        print("  ✓ Attenuated token created.")

        self.assertTrue(verify_token(child_token, root_kp.public_key, "files", "read"))
        self.assertFalse(verify_token(child_token, root_kp.public_key, "files", "write"))
        print("  ✓ Attenuated token correctly restricts scopes.")

        # ---- Chain to depth 2 -----------------------------------------------
        child_holder_kp = _extract_next_keypair(child_token)
        grandchild_kp = generate_child_keypair()
        token_d2 = attenuate_token(
            parent_token_b64=child_token,
            parent_keypair=child_holder_kp,
            child_agent_id=grandchild_kp.public_key.to_bytes().hex(),
            narrowed_scopes=["read"],
            ttl_seconds=600,
        )
        self.assertTrue(verify_token(token_d2, root_kp.public_key, "files", "read"))
        print("  ✓ Depth-2 token verified.")

        # ---- Chain to depth 3 (max) -----------------------------------------
        d2_holder_kp = _extract_next_keypair(token_d2)
        ggchild_kp = generate_child_keypair()
        token_d3 = attenuate_token(
            parent_token_b64=token_d2,
            parent_keypair=d2_holder_kp,
            child_agent_id=ggchild_kp.public_key.to_bytes().hex(),
            narrowed_scopes=["read"],
            ttl_seconds=600,
        )
        self.assertTrue(verify_token(token_d3, root_kp.public_key, "files", "read"))
        print("  ✓ Depth-3 token verified.")

        # ---- Depth > max_depth must fail -------------------------------------
        d3_holder_kp = _extract_next_keypair(token_d3)
        with self.assertRaises(ValueError):
            attenuate_token(
                parent_token_b64=token_d3,
                parent_keypair=d3_holder_kp,
                child_agent_id="attacker",
                narrowed_scopes=["read"],
                ttl_seconds=600,
            )
        print("  ✓ Depth ceiling enforced.")

    # ========================================================================
    # Test 02 — On-chain lineage registry + cascade revocation
    # ========================================================================

    def test_02_onchain_registry_and_cascade_revocation(self):
        print("\n--- Test 02: On-Chain Lineage Registry & Cascade Revocation ---")

        registry = self.deploy("LineageRegistry")
        print(f"  LineageRegistry deployed at {registry.address}")

        root = self.accounts[1]
        child = self.accounts[2]
        grandchild = self.accounts[3]

        # Register chain: root → child → grandchild
        zero = "0x0000000000000000000000000000000000000000"
        for agent, parent in [(root, zero), (child, root), (grandchild, child)]:
            tx = registry.functions.register(agent, parent).transact(
                {"from": self.accounts[0]}
            )
            self.w3.eth.wait_for_transaction_receipt(tx)

        # Depth
        self.assertEqual(registry.functions.depthOf(root).call(), 0)
        self.assertEqual(registry.functions.depthOf(child).call(), 1)
        self.assertEqual(registry.functions.depthOf(grandchild).call(), 2)
        print("  ✓ Lineage depths correct.")

        # Active status
        self.assertTrue(registry.functions.isActive(root).call())
        self.assertTrue(registry.functions.isActive(child).call())
        self.assertTrue(registry.functions.isActive(grandchild).call())
        print("  ✓ All agents active.")

        # Cascade revoke — revoking root deactivates entire subtree in O(1) walk
        tx = registry.functions.revoke(root).transact({"from": root})
        self.w3.eth.wait_for_transaction_receipt(tx)

        self.assertFalse(registry.functions.isActive(root).call())
        self.assertFalse(registry.functions.isActive(child).call())
        self.assertFalse(registry.functions.isActive(grandchild).call())
        print("  ✓ Cascade revocation verified (all descendants deactivated).")

    # ========================================================================
    # Test 03 — TLSNotary attestation + on-chain commitment
    # ========================================================================

    def test_03_tlsnotary_attestation_and_commitment(self):
        print("\n--- Test 03: TLSNotary Attestation & On-Chain Commitment ---")

        registry = self.deploy("LineageRegistry")

        session_id = init_tlsnotary_session("https://notary.example.com")
        self.assertIsNotNone(session_id)

        proof = execute_notarized_request(
            session_id=session_id,
            target_url="http://127.0.0.1:8545",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps(
                {"jsonrpc": "2.0", "method": "web3_clientVersion", "params": [], "id": 1}
            ).encode(),
        )
        self.assertIsNotNone(proof)
        self.assertEqual(proof["status"], 200)
        print("  ✓ TLSNotary proof generated.")

        # Fund agent account and commit proof hash on-chain
        agent_kp = KeyPair.generate()
        agent_account = Account.from_key(agent_kp.private_key.to_bytes())

        tx = self.w3.eth.send_transaction(
            {"from": self.accounts[0], "to": agent_account.address, "value": self.w3.to_wei(1, "ether")}
        )
        self.w3.eth.wait_for_transaction_receipt(tx)

        tx_hash = commit_proof_hash(proof, agent_kp, registry, self.w3)
        self.w3.eth.wait_for_transaction_receipt(tx_hash)

        proof_hash = calculate_proof_hash(proof)
        committer = registry.functions.proofCommitters(proof_hash).call()
        self.assertEqual(committer, agent_account.address)
        print("  ✓ Proof hash committed on-chain by agent.")

    # ========================================================================
    # Test 04 — Enforcement pipeline + trust scoring
    # ========================================================================

    def test_04_enforcement_and_trust_scoring(self):
        print("\n--- Test 04: Sequential Enforcement & Reputation Scoring ---")
        cls = self.__class__

        # Deploy isolated contract set
        registry = self.deploy("LineageRegistry")
        scorer = self.deploy("TrustScorer")
        enforcer = self.deploy("EnforcementLayer", registry.address, scorer.address)
        target = self.deploy("TargetContract")

        # Wire enforcer into TrustScorer
        tx = scorer.functions.setEnforcer(enforcer.address).transact({"from": cls.accounts[0]})
        cls.w3.eth.wait_for_transaction_receipt(tx)

        # ---- Setup root agent -----------------------------------------------
        root_kp = KeyPair.generate()
        root_acct = Account.from_key(root_kp.private_key.to_bytes())

        # Fund agent
        tx = cls.w3.eth.send_transaction(
            {"from": cls.accounts[0], "to": root_acct.address, "value": cls.w3.to_wei(1, "ether")}
        )
        cls.w3.eth.wait_for_transaction_receipt(tx)

        # Register root in lineage
        zero = "0x0000000000000000000000000000000000000000"
        tx = registry.functions.register(root_acct.address, zero).transact({"from": cls.accounts[0]})
        cls.w3.eth.wait_for_transaction_receipt(tx)

        # Mint root biscuit token
        root_token = mint_root_token(
            issuer_keypair=root_kp,
            agent_id="orchestrator",
            allowed_scopes=["read", "write"],
            max_depth=3,
            ttl_seconds=3600,
        )

        # Initial score must be 0
        self.assertEqual(scorer.functions.scoreOf(root_acct.address).call(), 0)

        # ---- Successful read action ------------------------------------------
        session_id = init_tlsnotary_session("https://notary.example.com")
        proof = execute_notarized_request(
            session_id=session_id,
            target_url="http://127.0.0.1:8545",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=b"read_api_call",
        )
        proof_hash = calculate_proof_hash(proof)

        # Commit proof hash on-chain
        tx_hash = commit_proof_hash(proof, root_kp, registry, cls.w3)
        cls.w3.eth.wait_for_transaction_receipt(tx_hash)

        # Build action: target.executeRead()
        read_data = target.functions.executeRead().build_transaction({"nonce": 0})["data"]
        action = (target.address, 0, read_data)

        # Compute token hash and sign delegation with agent's ECDSA key
        token_hash = _token_hash(root_token)
        v, r, s = _sign_delegation(root_acct, token_hash, proof_hash)

        # ABI-encode delegation: (tokenHash, agentAddress, proofHash, v, r, s)
        delegation = cls.w3.codec.encode(
            ["bytes32", "address", "bytes32", "uint8", "bytes32", "bytes32"],
            [token_hash, root_acct.address, proof_hash, v, r.to_bytes(32, "big"), s.to_bytes(32, "big")],
        )

        # Redeem — should succeed
        tx = enforcer.functions.redeemDelegation(delegation, action).transact({"from": cls.accounts[0]})
        cls.w3.eth.wait_for_transaction_receipt(tx)
        print("  ✓ redeemDelegation succeeded for read action.")

        score_after = scorer.functions.scoreOf(root_acct.address).call()
        self.assertGreater(score_after, 0)
        print(f"  ✓ Reputation score grew to {score_after}.")

        # ---- Violation: forged signature triggers revert ---------------------
        # A different agent (child) tries to claim the root token
        child_kp = generate_child_keypair()
        child_acct = Account.from_key(child_kp.private_key.to_bytes())

        # Fund child
        tx = cls.w3.eth.send_transaction(
            {"from": cls.accounts[0], "to": child_acct.address, "value": cls.w3.to_wei(1, "ether")}
        )
        cls.w3.eth.wait_for_transaction_receipt(tx)

        # Register child under root
        tx = registry.functions.register(child_acct.address, root_acct.address).transact(
            {"from": cls.accounts[0]}
        )
        cls.w3.eth.wait_for_transaction_receipt(tx)

        # Commit a different proof for the child
        proof_child = execute_notarized_request(
            session_id=session_id,
            target_url="http://127.0.0.1:8545",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=b"write_api_call",
        )
        proof_hash_child = calculate_proof_hash(proof_child)
        tx_hash = commit_proof_hash(proof_child, child_kp, registry, cls.w3)
        cls.w3.eth.wait_for_transaction_receipt(tx_hash)

        # Child signs the delegation themselves, but claims to be root_acct
        # The on-chain ECDSA recovery will reveal the signer is child_acct, not root_acct
        v_bad, r_bad, s_bad = _sign_delegation(child_acct, token_hash, proof_hash_child)
        
        # Build action
        write_data = target.functions.executeWrite().build_transaction({"nonce": 0})["data"]
        action_write = (target.address, 0, write_data)

        # Forge delegation: use root_acct address but child_acct's signature → mismatch
        forged_delegation = cls.w3.codec.encode(
            ["bytes32", "address", "bytes32", "uint8", "bytes32", "bytes32"],
            [token_hash, root_acct.address, proof_hash_child, v_bad, r_bad.to_bytes(32, "big"), s_bad.to_bytes(32, "big")],
        )

        # Should revert because ecrecover(digest, v, r, s) != root_acct
        with self.assertRaises(Exception) as ctx:
            enforcer.functions.redeemDelegation(forged_delegation, action_write).transact(
                {"from": cls.accounts[0]}
            )
        print("  ✓ Violation correctly blocked (ECDSA signature mismatch detected).")

        # ---- Verify maxDelegationDepth based on score -------------------------
        max_depth = scorer.functions.maxDelegationDepth(root_acct.address).call()
        self.assertGreaterEqual(max_depth, 1)
        print(f"  ✓ maxDelegationDepth for root agent: {max_depth}")


    # ========================================================================
    # Test 05 — ERC-4337 Integration (AgentAccount + MockEntryPoint)
    # ========================================================================

    def test_05_erc4337_integration(self):
        print("\n--- Test 05: ERC-4337 Integration (AgentAccount + MockEntryPoint) ---")
        cls = self.__class__

        # Deploy contracts
        registry = self.deploy("LineageRegistry")
        scorer = self.deploy("TrustScorer")
        enforcer = self.deploy("EnforcementLayer", registry.address, scorer.address)
        target = self.deploy("TargetContract")
        entrypoint = self.deploy("MockEntryPoint")

        # Wire enforcer
        tx = scorer.functions.setEnforcer(enforcer.address).transact({"from": cls.accounts[0]})
        cls.w3.eth.wait_for_transaction_receipt(tx)

        # Deploy AgentAccount
        account = self.deploy("AgentAccount", entrypoint.address, enforcer.address)
        print(f"  AgentAccount deployed at {account.address}")

        # Setup agent
        agent_kp = KeyPair.generate()
        agent_acct = Account.from_key(agent_kp.private_key.to_bytes())

        tx = cls.w3.eth.send_transaction({
            "from": cls.accounts[0],
            "to": agent_acct.address,
            "value": cls.w3.to_wei(1, "ether"),
        })
        cls.w3.eth.wait_for_transaction_receipt(tx)

        # Fund account contract (for gas)
        tx = cls.w3.eth.send_transaction({
            "from": cls.accounts[0],
            "to": account.address,
            "value": cls.w3.to_wei(0.1, "ether"),
        })
        cls.w3.eth.wait_for_transaction_receipt(tx)

        # Register agent in lineage (root)
        zero = "0x0000000000000000000000000000000000000000"
        tx = registry.functions.register(agent_acct.address, zero).transact({"from": cls.accounts[0]})
        cls.w3.eth.wait_for_transaction_receipt(tx)

        # Mint root biscuit token
        root_token = mint_root_token(
            issuer_keypair=agent_kp,
            agent_id="agent",
            allowed_scopes=["read"],
            max_depth=3,
            ttl_seconds=3600,
        )

        # Generate TLSNotary proof
        session_id = init_tlsnotary_session("https://notary.example.com")
        proof = execute_notarized_request(
            session_id=session_id,
            target_url="http://127.0.0.1:8545",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=b"read_api_call",
        )
        proof_hash = calculate_proof_hash(proof)

        # Commit proof on-chain
        tx_hash = commit_proof_hash(proof, agent_kp, registry, cls.w3)
        cls.w3.eth.wait_for_transaction_receipt(tx_hash)

        # Build action data: target.executeRead()
        read_data = target.functions.executeRead().build_transaction({"nonce": 0})["data"]

        # Compute token hash and sign delegation
        token_hash = _token_hash(root_token)
        v, r, s = _sign_delegation(agent_acct, token_hash, proof_hash)

        # ABI-encode delegation
        delegation = cls.w3.codec.encode(
            ["bytes32", "address", "bytes32", "uint8", "bytes32", "bytes32"],
            [token_hash, agent_acct.address, proof_hash, v, r.to_bytes(32, "big"), s.to_bytes(32, "big")],
        )

        # Build execute callData for AgentAccount: execute(target, value, data)
        execute_data = account.encode_abi("execute", args=[target.address, 0, read_data])

        # Compute userOpHash
        user_op_hash = cls.w3.keccak(text="test_user_op")

        # Call MockEntryPoint.testUserOp
        mock = cls.w3.eth.contract(address=entrypoint.address, abi=cls.artifacts["MockEntryPoint"]["abi"])
        tx = mock.functions.testUserOp(
            (
                account.address,
                0,
                execute_data,
                delegation,
                500000,
            ),
            user_op_hash,
            0,
        ).transact({"from": cls.accounts[0]})
        receipt = cls.w3.eth.wait_for_transaction_receipt(tx)

        self.assertEqual(receipt.status, 1, "ERC-4337 UserOperation should succeed")
        print("  ✓ ERC-4337 UserOperation flow succeeded via MockEntryPoint")

        # Verify the action executed correctly: target.data should be "hello"
        result = target.functions.data().call()
        self.assertEqual(result, "hello")
        print("  ✓ Target contract state updated via delegated execution")

        # Verify trust score increased
        score = scorer.functions.scoreOf(agent_acct.address).call()
        self.assertGreater(score, 0)
        print(f"  ✓ Trust score updated: {score}")


if __name__ == "__main__":
    unittest.main()
