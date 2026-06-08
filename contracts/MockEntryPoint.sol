// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "./AgentAccount.sol";

contract MockEntryPoint is IEntryPoint {
    struct UserOperationInfo {
        address sender;
        uint256 nonce;
        bytes callData;
        bytes signature;
        uint256 verificationGasLimit;
    }

    mapping(address => uint256) public nonces;

    function getNonce(address sender) external view override returns (uint256) {
        return nonces[sender];
    }

    function depositTo(address) external payable override {}

    function testUserOp(
        UserOperationInfo calldata op,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData) {
        UserOperation memory userOp = UserOperation({
            sender: op.sender,
            nonce: nonces[op.sender],
            initCode: "",
            callData: op.callData,
            callGasLimit: 1000000,
            verificationGasLimit: op.verificationGasLimit,
            preVerificationGas: 50000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: "",
            signature: op.signature
        });

        uint256 ret = IAccount(op.sender).validateUserOp{gas: op.verificationGasLimit}(
            userOp, userOpHash, missingAccountFunds
        );
        nonces[op.sender]++;

        (bool success, ) = op.sender.call{gas: 1000000}(op.callData);
        require(success, "MockEntryPoint: execution failed");

        return ret;
    }

    receive() external payable {}
}
