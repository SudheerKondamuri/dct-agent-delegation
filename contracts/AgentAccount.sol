// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "./EnforcementLayer.sol";

interface IEntryPoint {
    function getNonce(address sender) external view returns (uint256);
    function depositTo(address account) external payable;
}

struct UserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    uint256 callGasLimit;
    uint256 verificationGasLimit;
    uint256 preVerificationGas;
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
    bytes paymasterAndData;
    bytes signature;
}

interface IAccount {
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData);
}

contract AgentAccount is IAccount {
    IEntryPoint public immutable entryPoint;
    EnforcementLayer public immutable enforcer;

    bytes private _pendingDelegation;

    event AccountCreated(address indexed owner, address indexed entryPoint, address indexed enforcer);

    modifier onlyEntryPoint() {
        require(msg.sender == address(entryPoint), "Only entry point");
        _;
    }

    constructor(address _entryPoint, address _enforcer) {
        entryPoint = IEntryPoint(_entryPoint);
        enforcer = EnforcementLayer(_enforcer);
        emit AccountCreated(msg.sender, _entryPoint, _enforcer);
    }

    function validateUserOp(
        UserOperation calldata userOp,
        bytes32,
        uint256 missingAccountFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        require(userOp.sender == address(this), "Wrong sender");

        _pendingDelegation = userOp.signature;

        (address target, uint256 value, bytes memory actionData) = abi.decode(
            userOp.callData[4:],
            (address, uint256, bytes)
        );
        IDelegationManager.Action memory action = IDelegationManager.Action({
            target: target,
            value: value,
            data: actionData
        });

        enforcer.validateDelegation(userOp.signature, action);

        if (missingAccountFunds > 0) {
            payable(address(entryPoint)).transfer(missingAccountFunds);
        }

        return 0;
    }

    function execute(address target, uint256 value, bytes calldata data) external onlyEntryPoint {
        bytes memory delegation = _pendingDelegation;
        require(delegation.length > 0, "No pending delegation");
        delete _pendingDelegation;

        IDelegationManager.Action memory action = IDelegationManager.Action({
            target: target,
            value: value,
            data: data
        });

        enforcer.redeemDelegation(delegation, action);
    }

    receive() external payable {}
}
