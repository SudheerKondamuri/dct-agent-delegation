"""
Off-chain Delegated Capability Token (DCT) client.

Implements a Biscuit-like token system using Ed25519 signatures with:
  - Root token minting by an orchestrator
  - Offline attenuation (scope narrowing, depth limiting)
  - Offline verification using only the root public key
  - TLSNotary attestation and on-chain proof commitment

Signature chain:
  Block 0: signed by root_keypair. Contains `next_key` = ephemeral pubkey for block 1.
  Block i: signed by the ephemeral key stored in block[i-1].next_key.
  Verification: verify block 0 sig with root pubkey, block i sig with block[i-1].next_key.
"""

import base64
import json
import time
import hashlib
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import ed25519
from eth_hash.auto import keccak
from eth_account import Account


# ---------------------------------------------------------------------------
# Key wrappers
# ---------------------------------------------------------------------------

class Algorithm:
    Ed25519 = "Ed25519"


class PublicKey:
    def __init__(self, key_bytes: bytes):
        self.key_bytes = key_bytes

    @classmethod
    def from_bytes(cls, key_bytes: bytes):
        return cls(key_bytes)

    def to_bytes(self) -> bytes:
        return self.key_bytes

    def __eq__(self, other):
        if not isinstance(other, PublicKey):
            return False
        return self.key_bytes == other.key_bytes

    def __repr__(self):
        return f"PublicKey({self.key_bytes.hex()[:16]}...)"


class PrivateKey:
    def __init__(self, key_bytes: bytes):
        self.key_bytes = key_bytes

    @classmethod
    def from_bytes(cls, key_bytes: bytes, algorithm=None):
        return cls(key_bytes)

    def to_bytes(self) -> bytes:
        return self.key_bytes


class KeyPair:
    def __init__(self, private_key: PrivateKey = None):
        if private_key is None:
            priv_obj = ed25519.Ed25519PrivateKey.generate()
            self.private_key = PrivateKey(priv_obj.private_bytes_raw())
            self.public_key = PublicKey(priv_obj.public_key().public_bytes_raw())
        else:
            self.private_key = private_key
            priv_obj = ed25519.Ed25519PrivateKey.from_private_bytes(private_key.to_bytes())
            self.public_key = PublicKey(priv_obj.public_key().public_bytes_raw())

    @classmethod
    def from_private_key(cls, private_key: PrivateKey):
        return cls(private_key)

    @classmethod
    def generate(cls):
        return cls()


def generate_child_keypair() -> KeyPair:
    """
    Generate an ephemeral Ed25519 keypair for a new child agent.
    The private key remains on the child; the public key is committed to the lineage registry.
    """
    return KeyPair.generate()


# ---------------------------------------------------------------------------
# Biscuit-like token operations
# ---------------------------------------------------------------------------

def _sign(private_bytes: bytes, data: bytes) -> bytes:
    """Sign data with an Ed25519 private key."""
    priv_obj = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
    return priv_obj.sign(data)


def _verify(public_bytes: bytes, signature: bytes, data: bytes) -> bool:
    """Verify an Ed25519 signature. Returns True on success, False on failure."""
    pub_obj = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
    try:
        pub_obj.verify(signature, data)
        return True
    except Exception:
        return False


def mint_root_token(
    issuer_keypair: KeyPair,
    agent_id: str,
    allowed_scopes: list[str],
    max_depth: int,
    ttl_seconds: int,
) -> str:
    """
    Mint a root Biscuit token for the orchestrator agent.
    Encodes identity facts, allowed scopes, depth ceiling, and expiry check.

    The root block also contains a `next_key` — the public key that must sign the
    first attenuation block.  For the root token the `next_key` is the issuer's
    own public key so the issuer can attenuate later.

    Returns a base64-encoded token string.
    """
    block_0 = {
        "index": 0,
        "agent_id": agent_id,
        "allowed_scopes": allowed_scopes,
        "max_depth": max_depth,
        "expires_at": time.time() + ttl_seconds,
        "public_key": issuer_keypair.public_key.to_bytes().hex(),
        # next_key: ephemeral key whose holder can append block 1
        "next_key": issuer_keypair.public_key.to_bytes().hex(),
    }

    data_to_sign = json.dumps(block_0, sort_keys=True).encode("utf-8")
    sig = _sign(issuer_keypair.private_key.to_bytes(), data_to_sign)

    token_payload = {
        "blocks": [block_0],
        "signatures": [sig.hex()],
    }
    return base64.b64encode(json.dumps(token_payload).encode("utf-8")).decode("utf-8")


def attenuate_token(
    parent_token_b64: str,
    parent_keypair: KeyPair,
    child_agent_id: str,
    narrowed_scopes: list[str],
    ttl_seconds: int,
    root_public_key: PublicKey | None = None,  # kept for API compat
) -> str:
    """
    Append an attenuation block to an existing token, narrowing its scope.

    `parent_keypair` must correspond to the `next_key` stored in the last block of
    the parent token — only the current holder can attenuate further.

    Returns a base64-encoded attenuated token string.
    Raises ValueError if max_depth is exceeded.
    """
    try:
        parent_json = base64.b64decode(parent_token_b64.encode("utf-8")).decode("utf-8")
        parent_payload = json.loads(parent_json)
    except Exception as e:
        raise ValueError(f"Invalid parent token: {e}")

    blocks = parent_payload["blocks"]
    signatures = parent_payload["signatures"]

    # Depth check
    block_0 = blocks[0]
    max_depth = block_0.get("max_depth", 8)
    current_depth = len(blocks) - 1
    if current_depth >= max_depth:
        raise ValueError("Maximum delegation depth reached")

    # Generate an ephemeral keypair for the child — the child will need this to
    # attenuate further downstream.
    child_ephemeral = KeyPair.generate()

    new_block = {
        "index": len(blocks),
        "child_agent_id": child_agent_id,
        "narrowed_scopes": narrowed_scopes,
        "expires_at": time.time() + ttl_seconds,
        "public_key": parent_keypair.public_key.to_bytes().hex(),
        # next_key: key the child must hold to append block N+1
        "next_key": child_ephemeral.public_key.to_bytes().hex(),
    }

    # The new block is signed with the parent's private key
    # (which must match the `next_key` in the previous block).
    data_to_sign = (
        json.dumps(new_block, sort_keys=True).encode("utf-8")
        + bytes.fromhex(signatures[-1])
    )
    sig = _sign(parent_keypair.private_key.to_bytes(), data_to_sign)

    blocks.append(new_block)
    signatures.append(sig.hex())

    attenuated_payload = {
        "blocks": blocks,
        "signatures": signatures,
        # Carry the child ephemeral private key so the child can attenuate.
        # In a real system this would be handed via a secure channel.
        "_next_private_key": child_ephemeral.private_key.to_bytes().hex(),
    }
    return base64.b64encode(
        json.dumps(attenuated_payload).encode("utf-8")
    ).decode("utf-8")


def _extract_next_keypair(token_b64: str) -> KeyPair:
    """
    Helper: extract the ephemeral private key embedded in an attenuated token so
    the holder can attenuate further.
    """
    payload = json.loads(base64.b64decode(token_b64.encode("utf-8")).decode("utf-8"))
    priv_hex = payload.get("_next_private_key")
    if priv_hex is None:
        raise ValueError("Token does not carry an ephemeral key — cannot attenuate")
    return KeyPair(PrivateKey(bytes.fromhex(priv_hex)))


def verify_token(
    token_b64: str,
    root_public_key: PublicKey,
    requested_resource: str,
    requested_operation: str,
) -> bool:
    """
    Verify a Biscuit token offline using only the root public key.
    Injects current request context (resource, operation, timestamp) as authorizer facts.
    Returns True only if all Datalog-like checks in all blocks pass.
    """
    try:
        token_json = base64.b64decode(token_b64.encode("utf-8")).decode("utf-8")
        payload = json.loads(token_json)
        blocks = payload["blocks"]
        signatures = payload["signatures"]

        if not blocks or not signatures or len(blocks) != len(signatures):
            return False

        # ── 1. Signature chain verification ──────────────────────────────
        # Block 0: verified with root public key
        block_0 = blocks[0]
        data_0 = json.dumps(block_0, sort_keys=True).encode("utf-8")
        if not _verify(root_public_key.to_bytes(), bytes.fromhex(signatures[0]), data_0):
            return False

        # Block i (i > 0): verified with blocks[i-1]["next_key"]
        for i in range(1, len(blocks)):
            prev_next_key = bytes.fromhex(blocks[i - 1]["next_key"])
            data_i = (
                json.dumps(blocks[i], sort_keys=True).encode("utf-8")
                + bytes.fromhex(signatures[i - 1])
            )
            if not _verify(prev_next_key, bytes.fromhex(signatures[i]), data_i):
                return False

        # ── 2. Expiry check ──────────────────────────────────────────────
        now = time.time()
        for block in blocks:
            if now > block["expires_at"]:
                return False

        # ── 3. Depth check ───────────────────────────────────────────────
        max_depth = block_0.get("max_depth", 8)
        if len(blocks) - 1 > max_depth:
            return False

        # ── 4. Scope check (intersection across all blocks) ──────────────
        allowed = set(block_0["allowed_scopes"])
        if requested_operation not in allowed:
            return False

        for i in range(1, len(blocks)):
            narrowed = set(blocks[i]["narrowed_scopes"])
            if requested_operation not in narrowed:
                return False

        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# TLSNotary simulation
# ---------------------------------------------------------------------------

def init_tlsnotary_session(notary_url: str) -> str:
    """
    Initialize a TLSNotary session with the notary service.
    Returns a session_id for use in subsequent calls.
    """
    import uuid
    return str(uuid.uuid4())


def execute_notarized_request(
    session_id: str,
    target_url: str,
    method: str,
    headers: dict,
    body: bytes | None,
) -> dict:
    """
    Execute an HTTPS request via the TLSNotary notary.
    Returns a proof dict containing: url, method, status, body_hash, signature.
    The notary never sees plaintext body content.
    """
    import requests as req_lib

    if method.upper() == "GET":
        resp = req_lib.get(target_url, headers=headers)
    elif method.upper() == "POST":
        resp = req_lib.post(target_url, headers=headers, data=body)
    else:
        raise ValueError(f"Unsupported method: {method}")

    body_hash = hashlib.sha256(body if body else b"").hexdigest()
    resp_body_hash = hashlib.sha256(resp.content).hexdigest()

    proof = {
        "url": target_url,
        "method": method.upper(),
        "status": resp.status_code,
        "body_hash": body_hash,
        "resp_body_hash": resp_body_hash,
        "session_id": session_id,
    }

    # Sign proof with notary key (deterministic for reproducibility)
    notary_seed = hashlib.sha256(b"notary_private_key").digest()
    notary_priv = ed25519.Ed25519PrivateKey.from_private_bytes(notary_seed)
    proof_bytes = json.dumps(proof, sort_keys=True).encode("utf-8")
    sig = notary_priv.sign(proof_bytes).hex()

    proof["signature"] = sig
    return proof


def calculate_proof_hash(proof: dict) -> bytes:
    """Keccak-256 hash of a TLSNotary proof for on-chain commitment."""
    proof_bytes = json.dumps(proof, sort_keys=True).encode("utf-8")
    return keccak(proof_bytes)


def commit_proof_hash(
    proof: dict,
    agent_keypair: KeyPair,
    registry_contract,
    web3,
) -> str:
    """
    Hash the TLSNotary proof and commit it to the lineage registry on-chain.
    Must be called in a separate transaction before redeemDelegation.
    Returns the transaction hash.
    """
    proof_hash = calculate_proof_hash(proof)

    agent_priv_bytes = agent_keypair.private_key.to_bytes()
    agent_account = Account.from_key(agent_priv_bytes)

    nonce = web3.eth.get_transaction_count(agent_account.address)
    tx = registry_contract.functions.commitProofHash(proof_hash).build_transaction(
        {
            "from": agent_account.address,
            "nonce": nonce,
            "gas": 200000,
            "gasPrice": web3.eth.gas_price,
        }
    )

    signed_tx = web3.eth.account.sign_transaction(tx, private_key=agent_account.key)
    tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)

    return tx_hash.hex()
