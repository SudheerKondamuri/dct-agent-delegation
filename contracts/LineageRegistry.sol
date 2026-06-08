// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract LineageRegistry {
    uint8 public constant MAX_DEPTH = 8;

    struct AgentInfo {
        address parent;
        bool registered;
        bool revoked;
        uint8 depth;
    }

    mapping(address => AgentInfo) public agents;
    mapping(bytes32 => address) public proofCommitters;

    event Registered(address indexed agent, address indexed parent, uint8 depth);
    event Revoked(address indexed agent, address indexed revokedBy);
    event ProofCommitted(bytes32 indexed proofHash, address indexed committer);

    // Register a new agent and its parent relationship.
    // Reverts if depth would exceed MAX_DEPTH or if parent is not registered (except for root).
    function register(address agent, address parent) external {
        require(agent != address(0), "Invalid agent address");
        require(!agents[agent].registered, "Agent already registered");

        uint8 newDepth = 0;
        if (parent != address(0)) {
            require(agents[parent].registered, "Parent not registered");
            newDepth = agents[parent].depth + 1;
            require(newDepth <= MAX_DEPTH, "Max depth exceeded");
        } else {
            newDepth = 0;
        }

        agents[agent] = AgentInfo({
            parent: parent,
            registered: true,
            revoked: false,
            depth: newDepth
        });

        emit Registered(agent, parent, newDepth);
    }

    // Mark an agent as revoked.
    // Caller must be the agent itself or its direct registered parent.
    function revoke(address agent) external {
        require(agents[agent].registered, "Agent not registered");
        require(
            msg.sender == agent || msg.sender == agents[agent].parent,
            "Not authorized to revoke"
        );

        agents[agent].revoked = true;
        emit Revoked(agent, msg.sender);
    }

    // Walk the lineage from agent to root.
    // Returns false if any node in the path is marked revoked or if agent is not registered.
    // Bounded by MAX_DEPTH iterations — no unbounded loops.
    function isActive(address agent) public view returns (bool) {
        if (!agents[agent].registered) {
            return false;
        }

        address current = agent;
        for (uint256 i = 0; i <= MAX_DEPTH; i++) {
            if (agents[current].revoked) {
                return false;
            }
            address parent = agents[current].parent;
            if (parent == address(0)) {
                return true;
            }
            current = parent;
        }
        return true;
    }

    // Return the depth of an agent in the delegation tree.
    function depthOf(address agent) external view returns (uint8) {
        require(agents[agent].registered, "Agent not registered");
        return agents[agent].depth;
    }

    // Commit a proof hash to the registry
    function commitProofHash(bytes32 proofHash) external {
        require(proofCommitters[proofHash] == address(0), "Proof already committed");
        proofCommitters[proofHash] = msg.sender;
        emit ProofCommitted(proofHash, msg.sender);
    }
}
