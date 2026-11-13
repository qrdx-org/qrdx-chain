// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// A minimal 6-decimal ERC-20 for the bridge's end-to-end test: the whole supply to its deployer.
contract TestToken {
    string public constant name = "Test USD";
    string public constant symbol = "TUSD";
    uint8 public constant decimals = 6;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(uint256 supply) {
        totalSupply = supply;
        balanceOf[msg.sender] = supply;
        emit Transfer(address(0), msg.sender, supply);
    }

    function transfer(address to, uint256 v) external returns (bool) {
        _move(msg.sender, to, v);
        return true;
    }

    function approve(address s, uint256 v) external returns (bool) {
        allowance[msg.sender][s] = v;
        emit Approval(msg.sender, s, v);
        return true;
    }

    function transferFrom(address f, address to, uint256 v) external returns (bool) {
        require(allowance[f][msg.sender] >= v, "allowance");
        allowance[f][msg.sender] -= v;
        _move(f, to, v);
        return true;
    }

    function _move(address f, address to, uint256 v) private {
        require(balanceOf[f] >= v, "balance");
        balanceOf[f] -= v;
        balanceOf[to] += v;
        emit Transfer(f, to, v);
    }
}
