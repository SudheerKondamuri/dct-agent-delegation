// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "./LineageRegistry.sol";
import "./TrustScorer.sol";

interface IDelegationManager {
    struct Action {
        address target;
        uint256 value;
        bytes data;
    }

    function redeemDelegation(
        bytes calldata delegation,
        Action calldata action
    ) external returns (bytes memory);
}

error LineageInactive(address agent);
error BiscuitSignatureMismatch(address agent);
error ScopeViolation(address agent);
error TLSProofInvalid(address agent);

contract EnforcementLayer is IDelegationManager {
    LineageRegistry public registry;
    TrustScorer public trustScorer;

    mapping(bytes32 => bool) public usedProofs;

    bytes4 public constant READ_SELECTOR = bytes4(keccak256("executeRead()"));
    bytes4 public constant WRITE_SELECTOR = bytes4(keccak256("executeWrite()"));

    event DelegationRedeemed(address indexed agent, address indexed target, bytes4 selector);
    event ViolationDetected(address indexed agent, string reason);

    constructor(address _registry, address _trustScorer) {
        registry = LineageRegistry(_registry);
        trustScorer = TrustScorer(_trustScorer);
    }

    // Run all 4 validation checks without executing the action.
    // Called during ERC-4337 UserOperation validation phase.
    function validateDelegation(
        bytes calldata delegation,
        Action calldata action
    ) public view {
        (bytes32 tokenHash, address agent, bytes32 proofHash, uint8 v, bytes32 r, bytes32 s) = abi.decode(
            delegation,
            (bytes32, address, bytes32, uint8, bytes32, bytes32)
        );

        if (!registry.isActive(agent)) {
            revert LineageInactive(agent);
        }

        bytes32 digest = keccak256(abi.encodePacked(tokenHash, proofHash));
        address signer = ecrecover(digest, v, r, s);
        if (signer != agent) {
            revert BiscuitSignatureMismatch(agent);
        }

        if (!_scopePermits(tokenHash, action)) {
            revert ScopeViolation(agent);
        }

        if (!_verifyTLSProof(proofHash)) {
            revert TLSProofInvalid(agent);
        }
    }

    function redeemDelegation(
        bytes calldata delegation,
        Action calldata action
    ) external override returns (bytes memory) {
        (bytes32 tokenHash, address agent, bytes32 proofHash, uint8 v, bytes32 r, bytes32 s) = abi.decode(
            delegation,
            (bytes32, address, bytes32, uint8, bytes32, bytes32)
        );

        // ① Lineage validity
        if (!registry.isActive(agent)) {
            _slash(agent);
            emit ViolationDetected(agent, "lineage_inactive");
            revert LineageInactive(agent);
        }

        // ② Token signature verification
        bytes32 digest = keccak256(abi.encodePacked(tokenHash, proofHash));
        address signer = ecrecover(digest, v, r, s);
        if (signer != agent) {
            _slash(agent);
            emit ViolationDetected(agent, "biscuit_sig_mismatch");
            revert BiscuitSignatureMismatch(agent);
        }

        // ③ Scope validation
        if (!_scopePermits(tokenHash, action)) {
            _slash(agent);
            emit ViolationDetected(agent, "scope_violation");
            revert ScopeViolation(agent);
        }

        // ④ TLSNotary attestation
        if (!_verifyTLSProof(proofHash)) {
            _slash(agent);
            emit ViolationDetected(agent, "tls_proof_invalid");
            revert TLSProofInvalid(agent);
        }

        usedProofs[proofHash] = true;

        bytes4 selector;
        if (action.data.length >= 4) {
            selector = bytes4(action.data[0:4]);
        }

        (bool success, bytes memory result) = action.target.call{value: action.value}(action.data);
        require(success, "EnforcementLayer: action execution reverted");

        if (address(trustScorer) != address(0)) {
            trustScorer.onSuccess(agent);
        }

        emit DelegationRedeemed(agent, action.target, selector);
        return result;
    }

    function _slash(address agent) internal {
        if (address(trustScorer) != address(0)) {
            trustScorer.onViolation(agent);
        }
    }

    function _scopePermits(
        bytes32,
        Action calldata action
    ) public pure returns (bool) {
        if (action.data.length < 4) {
            return false;
        }
        bytes4 selector = bytes4(action.data[0:4]);
        return selector == READ_SELECTOR || selector == WRITE_SELECTOR;
    }

    function _verifyTLSProof(bytes32 proofHash) public view returns (bool) {
        if (usedProofs[proofHash]) {
            return false;
        }
        return registry.proofCommitters(proofHash) != address(0);
    }
}
