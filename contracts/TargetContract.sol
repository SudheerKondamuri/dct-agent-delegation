// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract TargetContract {
    string public data = "hello";
    
    function executeRead() external view returns (string memory) {
        return data;
    }
    
    function executeWrite() external {
        data = "world";
    }
}
