// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract TrustScorer {
    address public owner;
    address public enforcer;

    // Reputation score per agent (scaled by 1000)
    mapping(address => uint256) public scores;

    // Constants for score growth
    uint256 public constant SUCCESS_DELTA = 100; // 0.10 scaled by 1000? No, SUCCESS_DELTA is scaled by 1000, say 100 (0.10)
    uint256 public constant LOG_SCALE = 1000;
    uint256 public constant VIOLATION_SLASH = 500; // 0.50 scaled by 1000

    event ScoreUpdated(address indexed agent, uint256 newScore);

    modifier onlyEnforcer() {
        require(msg.sender == enforcer, "Only enforcer can call");
        _;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setEnforcer(address _enforcer) external onlyOwner {
        enforcer = _enforcer;
    }

    // Called by the enforcement layer after a successful action.
    // Increments score using logarithmic growth: Δ = SUCCESS_DELTA * log2(score+1) / LOG_SCALE
    function onSuccess(address agent) external onlyEnforcer {
        uint256 currentScore = scores[agent];
        
        // Logarithmic delta: SUCCESS_DELTA * log2(currentScore + 1) / LOG_SCALE
        // Since score is scaled by 1000, "score + 1" in real number corresponds to "currentScore + 1000" in fixed point!
        uint256 logVal = log2Fixed(currentScore + 1000);
        uint256 delta = (SUCCESS_DELTA * logVal) / LOG_SCALE;
        
        // If delta is 0, give a tiny base bump to ensure score always advances on success
        if (delta == 0) {
            delta = 10; // 0.01 bump
        }
        
        scores[agent] = currentScore + delta;
        emit ScoreUpdated(agent, scores[agent]);
    }

    // Called by the enforcement layer after a scope violation or failed attestation.
    // Slashes score by VIOLATION_SLASH; score cannot go below zero.
    function onViolation(address agent) external onlyEnforcer {
        uint256 currentScore = scores[agent];
        if (currentScore > VIOLATION_SLASH) {
            scores[agent] = currentScore - VIOLATION_SLASH;
        } else {
            scores[agent] = 0;
        }
        emit ScoreUpdated(agent, scores[agent]);
    }

    // Return the current score for an agent.
    function scoreOf(address agent) external view returns (uint256) {
        return scores[agent];
    }

    // Return the maximum delegation depth the agent is currently permitted to initiate.
    // Used by orchestrators before minting an attenuated token.
    function maxDelegationDepth(address agent) external view returns (uint8) {
        uint256 score = scores[agent];
        if (score < 500) {
            return 1;
        } else if (score < 1000) {
            return 3;
        } else if (score < 2000) {
            return 5;
        } else {
            return 8;
        }
    }

    // High precision fixed-point log2(x / 1000) scaled by 1000
    function log2Fixed(uint256 x) public pure returns (uint256) {
        if (x < 1000) {
            return 0;
        }
        
        // Calculate integer part
        uint256 integerPart = 0;
        uint256 temp = x;
        while (temp >= 2) {
            integerPart++;
            temp /= 2;
        }
        
        // y is in [1e18, 2e18)
        uint256 y = (x * 1e18) / (1 << integerPart);
        
        // Calculate fractional part using binary search/square-root method (10 iterations)
        uint256 fractionalPart = 0;
        uint256 factor = 500; // 0.5 * 1000
        
        for (uint256 i = 0; i < 10; i++) {
            y = (y * y) / 1e18;
            if (y >= 2e18) {
                fractionalPart += factor;
                y /= 2;
            }
            factor /= 2;
        }
        
        uint256 log2XScaled = (integerPart * 1000) + fractionalPart;
        
        // Subtract log2(1000) which is approx 9965 (2^9.96578 = 1000)
        if (log2XScaled >= 9965) {
            return log2XScaled - 9965;
        } else {
            return 0;
        }
    }
}
