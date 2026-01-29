// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleStorage {
    uint256 private storedValue;
    
    event ValueChanged(uint256 indexed oldValue, uint256 indexed newValue);
    
    function setValue(uint256 value) public {
        emit ValueChanged(storedValue, value);
        storedValue = value;
    }
    
    function getValue() public view returns (uint256) {
        return storedValue;
    }
    
    function increment() public {
        storedValue += 1;
    }
}
