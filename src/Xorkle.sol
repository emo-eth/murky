// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./common/MurkyBase.sol";

/// @notice Nascent, simple, kinda efficient (and improving!) Merkle proof generator and verifier
/// @author dmfxyz
/// @dev Note Xor Based "Merkle" Tree
contract Xorkle is MurkyBase {
    /********************
     * HASHING FUNCTION *
     ********************/

    function hashLeafPairs(bytes32 left, bytes32 right) public pure override returns (bytes32 _hash) {
        // saves a few gas lol
        assembly {
            mstore(0x0, xor(left, right))
            _hash := keccak256(0x0, 0x20)
        }
    }

    /********************
     * PROOF GENERATION *
     ********************/

    function getRoot(bytes32[] memory data) public pure override returns (bytes32) {
        require(data.length > 1, "won't generate root for single leaf");
        while (data.length > 1) {
            data = hashLevel(data);
        }
        return data[0];
    }

    function getProof(bytes32[] memory data, uint256 node) public pure override returns (bytes32[] memory result) {
        require(data.length > 1, "won't generate proof for single leaf");
        // The size of the proof is equal to the ceiling of log2(numLeaves)
        // Two overflow risks: node, pos
        // node: max array size is 2**256-1. Largest index in the array will be 1 less than that. Also,
        // for dynamic arrays, size is limited to 2**64-1
        // pos: pos is bounded by log2(data.length), which should be less than type(uint256).max
        uint256 resultIndexPtr;
        uint256 length;
        assembly {
            result := mload(0x40)
            resultIndexPtr := add(0x20, result)
        }
        while (data.length > 1) {
            assembly {
                let oddNodeIndex := and(node, 1)
                let lastNodeIndex := eq(mload(data), add(1, node))
                let switchVal := or(shl(1, lastNodeIndex), oddNodeIndex)
                switch switchVal
                // neither odd nor last
                case 0 {
                    // get pointer to result[node+1] by adding 2 to node and multiplying by 0x20
                    // to account for the fact that result points to array length, not first index
                    mstore(resultIndexPtr, mload(add(data, mul(0x20, add(2, node)))))
                }
                // node is last
                case 2 {
                    mstore(resultIndexPtr, 0)
                }
                // node is odd (and possibly also last)
                default {
                    mstore(resultIndexPtr, mload(add(data, mul(0x20, node))))
                }
                resultIndexPtr := add(0x20, resultIndexPtr)
                node := div(node, 2)
                length := add(1, length)
            }
            data = hashLevel(data);
        }
        assembly {
            // TODO: test length and result free mem ptr get set correctly
            mstore(result, length)
            mstore(0x40, resultIndexPtr)
        }
        return result;
    }

    ///@dev function is private to prevent unsafe data from being passed
    function hashLevel(bytes32[] memory data) internal pure override returns (bytes32[] memory result) {
        // bytes32[] memory result;

        // Function is private, and all internal callers check that data.length >=2.
        // Underflow is not possible as lowest possible value for data/result index is 1
        // overflow should be safe as length is / 2 always.

        // declare these variables outside of loop and assembly scope
        uint256 length;
        uint256 newLength;
        uint256 resultIndexPointer;
        uint256 dataIndexPointer;
        uint256 stopIteration;
        bool hashLast;
        assembly {
            // we will be modifying data in-place, so set result pointer to data pointer
            result := data
            // get length of original data array
            length := mload(data)
            switch and(length, 1)
            case 1 {
                // if length is odd, add 1 so division by 2 will round up
                newLength := add(1, div(length, 2))
                // note that we will need to hash the last element of data with 0 to get last element of result array
                hashLast := 1
                // todo: hash last node with zero
            }
            default {
                newLength := div(length, 2)
            }
            mstore(data, newLength)
            resultIndexPointer := add(0x20, data)
            dataIndexPointer := resultIndexPointer
            // stop iterating over for loop at length-1
            stopIteration := add(data, mul(length, 0x20))
        }
        for (; dataIndexPointer < stopIteration; ) {
            bytes32 data1;
            bytes32 data2;
            assembly {
                data1 := mload(dataIndexPointer)
                data2 := mload(add(dataIndexPointer, 0x20))
            }
            bytes32 hashedPair = hashLeafPairs(data1, data2);
            assembly {
                mstore(resultIndexPointer, hashedPair)
                resultIndexPointer := add(0x20, resultIndexPointer)
                dataIndexPointer := add(0x40, dataIndexPointer)
            }
        }
        if (hashLast) {
            bytes32 data1;
            assembly {
                data1 := mload(add(data, mul(0x20, length)))
            }
            bytes32 hashedPair = hashLeafPairs(data1, bytes32(0));
            assembly {
                mstore(resultIndexPointer, hashedPair)
            }
        }
    }
}
