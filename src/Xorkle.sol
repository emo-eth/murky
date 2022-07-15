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

    function getRoot(bytes32[] memory data) external pure override returns (bytes32 result) {
        require(data.length > 1, "won't generate root for single leaf");
        assembly {
            function hashLeafPairs(left, right) -> _hash {
                mstore(0x0, xor(left, right))
                _hash := keccak256(0x0, 0x20)
            }
            function hashLevel(_data, length) -> newLength {
                // we will be modifying data in-place, so set result pointer to data pointer
                let _result := _data
                // get length of original data array
                // let length := mload(_data)
                // bool to track if we need to hash the last element of an odd-length array with zero
                let hashLast

                // if length is odd, we need to hash the last element with zero
                switch and(length, 1)
                case 1 {
                    // if length is odd, add 1 so division by 2 will round up
                    newLength := add(1, div(length, 2))
                    hashLast := 1
                }
                default {
                    newLength := div(length, 2)
                }
                // todo: necessary?
                // mstore(_data, newLength)
                let resultIndexPointer := add(0x20, _data)
                let dataIndexPointer := resultIndexPointer

                // stop iterating over for loop at length-1
                let stopIteration := add(_data, mul(length, 0x20))
                // write result array in-place over data array
                for {

                } lt(dataIndexPointer, stopIteration) {

                } {
                    // get next two elements from data, hash them together
                    let data1 := mload(dataIndexPointer)
                    let data2 := mload(add(dataIndexPointer, 0x20))
                    let hashedPair := hashLeafPairs(data1, data2)
                    // overwrite an element of data array with
                    mstore(resultIndexPointer, hashedPair)
                    // increment result pointer by 1 slot
                    resultIndexPointer := add(0x20, resultIndexPointer)
                    // increment data pointer by 2 slot
                    dataIndexPointer := add(0x40, dataIndexPointer)
                }
                // we did not yet hash last index if odd-length
                if hashLast {
                    let data1 := mload(dataIndexPointer)
                    let hashedPair := hashLeafPairs(data1, 0)
                    mstore(resultIndexPointer, hashedPair)
                }
            }

            let dataLength := mload(data)
            for {

            } gt(dataLength, 1) {

            } {
                dataLength := hashLevel(data, dataLength)
            }
            result := mload(add(0x20, data))
        }
    }

    function getProof(bytes32[] memory data, uint256 node) external pure override returns (bytes32[] memory result) {
        require(data.length > 1, "won't generate proof for single leaf");
        // The size of the proof is equal to the ceiling of log2(numLeaves)
        // Two overflow risks: node, pos
        // node: max array size is 2**256-1. Largest index in the array will be 1 less than that. Also,
        // for dynamic arrays, size is limited to 2**64-1
        // pos: pos is bounded by log2(data.length), which should be less than type(uint256).max
        // uint256 resultIndexPtr;
        // uint256 length;
        assembly {
            function hashLeafPairs(left, right) -> _hash {
                mstore(0x0, xor(left, right))
                _hash := keccak256(0x0, 0x20)
            }
            function hashLevel(_data, length) -> newLength {
                // we will be modifying data in-place, so set result pointer to data pointer
                let _result := _data
                // get length of original data array
                // let length := mload(_data)
                // bool to track if we need to hash the last element of an odd-length array with zero
                let hashLast

                // if length is odd, we'll need to hash the last element with zero
                switch and(length, 1)
                case 1 {
                    // if length is odd, add 1 so division by 2 will round up
                    newLength := add(1, div(length, 2))
                    hashLast := 1
                }
                default {
                    newLength := div(length, 2)
                }
                // todo: necessary?
                // mstore(_data, newLength)
                let resultIndexPointer := add(0x20, _data)
                let dataIndexPointer := resultIndexPointer

                // stop iterating over for loop at length-1
                let stopIteration := add(_data, mul(length, 0x20))
                // write result array in-place over data array
                for {

                } lt(dataIndexPointer, stopIteration) {

                } {
                    // get next two elements from data, hash them together
                    let data1 := mload(dataIndexPointer)
                    let data2 := mload(add(dataIndexPointer, 0x20))
                    let hashedPair := hashLeafPairs(data1, data2)
                    // overwrite an element of data array with
                    mstore(resultIndexPointer, hashedPair)
                    // increment result pointer by 1 slot
                    resultIndexPointer := add(0x20, resultIndexPointer)
                    // increment data pointer by 2 slot
                    dataIndexPointer := add(0x40, dataIndexPointer)
                }
                // we did not yet hash last index if odd-length
                if hashLast {
                    let data1 := mload(dataIndexPointer)
                    let hashedPair := hashLeafPairs(data1, 0)
                    mstore(resultIndexPointer, hashedPair)
                }
            }

            // set result pointer to free memory
            result := mload(0x40)
            // get pointer to first index of result
            let resultIndexPtr := add(0x20, result)
            // declare so we can use later
            let newLength
            // put length of data onto stack
            let dataLength := mload(data)
            for {
                // repeat until only one element is left
            } gt(dataLength, 1) {

            } {
                // bool if node is odd
                let oddNodeIndex := and(node, 1)
                // bool if node is last
                let lastNodeIndex := eq(dataLength, add(1, node))
                // store both bools in one value so we can switch on it
                let switchVal := or(shl(1, lastNodeIndex), oddNodeIndex)
                switch switchVal
                // 00 - neither odd nor last
                case 0 {
                    // store data[node+1] at result[i]
                    // get pointer to result[node+1] by adding 2 to node and multiplying by 0x20
                    // to account for the fact that result points to array length, not first index
                    mstore(resultIndexPtr, mload(add(data, mul(0x20, add(2, node)))))
                }
                // 10 - node is last
                case 2 {
                    // store 0 at result[i]
                    mstore(resultIndexPtr, 0)
                }
                // 01 or 11 - node is odd (and possibly also last)
                default {
                    // store data[node-1] at result[i]
                    mstore(resultIndexPtr, mload(add(data, mul(0x20, node))))
                }
                // increment result index
                resultIndexPtr := add(0x20, resultIndexPtr)

                // get new node index
                node := div(node, 2)
                // keep track of how long result array is
                newLength := add(1, newLength)
                // compute the next hash level, overwriting data, and get the new length
                dataLength := hashLevel(data, dataLength)
            }
            // store length of result array at pointer
            mstore(result, newLength)
            // set free mem pointer to word after end of result array
            mstore(0x40, resultIndexPtr)
        }
    }
}
