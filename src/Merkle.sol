// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./common/MurkyBase.sol";

/// @notice Nascent, simple, kinda efficient (and improving!) Merkle proof generator and verifier
/// @author dmfxyz
/// @dev Note Generic Merkle Tree
contract Merkle is MurkyBase {
    /********************
     * HASHING FUNCTION *
     ********************/

    /// ascending sort and concat prior to hashing
    function hashLeafPairs(bytes32 left, bytes32 right) public pure override returns (bytes32 _hash) {
        assembly {
            switch lt(left, right)
            case 0 {
                mstore(0x0, right)
                mstore(0x20, left)
            }
            default {
                mstore(0x0, left)
                mstore(0x20, right)
            }
            _hash := keccak256(0x0, 0x40)
        }
    }

    /********************
     * PROOF GENERATION *
     ********************/

    function getRoot(bytes32[] memory data) public pure override returns (bytes32 result) {
        require(data.length > 1, "won't generate root for single leaf");
        assembly {
            function hashLeafPairs(left, right) -> _hash {
                switch lt(left, right)
                case 0 {
                    mstore(0x0, right)
                    mstore(0x20, left)
                }
                default {
                    mstore(0x0, left)
                    mstore(0x20, right)
                }
                _hash := keccak256(0x0, 0x40)
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

    function getProof(bytes32[] memory data, uint256 node) public pure override returns (bytes32[] memory result) {
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
                switch lt(left, right)
                case 0 {
                    mstore(0x0, right)
                    mstore(0x20, left)
                }
                default {
                    mstore(0x0, left)
                    mstore(0x20, right)
                }
                _hash := keccak256(0x0, 0x40)
            }
            function hashLevel(_data, length) -> newLength {
                // we will be modifying data in-place, so set result pointer to data pointer
                let _result := _data
                // get length of original data array
                // let length := mload(_data)
                let hashLast

                switch and(length, 1)
                case 1 {
                    // if length is odd, add 1 so division by 2 will round up
                    newLength := add(1, div(length, 2))
                    // note that we will need to hash the last element of data with 0 to get last element of result array
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

                for {

                } lt(dataIndexPointer, stopIteration) {

                } {
                    let data1 := mload(dataIndexPointer)
                    let data2 := mload(add(dataIndexPointer, 0x20))
                    let hashedPair := hashLeafPairs(data1, data2)
                    mstore(resultIndexPointer, hashedPair)
                    resultIndexPointer := add(0x20, resultIndexPointer)
                    dataIndexPointer := add(0x40, dataIndexPointer)
                }
                if hashLast {
                    let data1 := mload(add(_data, mul(0x20, length)))
                    let hashedPair := hashLeafPairs(data1, 0)
                    mstore(resultIndexPointer, hashedPair)
                }
            }

            result := mload(0x40)
            let resultIndexPtr := add(0x20, result)
            let newLength
            let dataLength := mload(data)
            for {

            } gt(dataLength, 1) {

            } {
                let oddNodeIndex := and(node, 1)
                let lastNodeIndex := eq(dataLength, add(1, node))
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
                newLength := add(1, newLength)

                dataLength := hashLevel(data, dataLength)
            }

            mstore(result, newLength)
            mstore(0x40, resultIndexPtr)
        }
        // return result;
    }

    ///@dev function is private to prevent unsafe data from being passed
    // TODO: remove, unused
    function hashLevel(bytes32[] memory data) internal pure virtual override returns (bytes32[] memory result) {
        // bytes32[] memory result;

        // Function is private, and all internal callers check that data.length >=2.
        // Underflow is not possible as lowest possible value for data/result index is 1
        // overflow should be safe as length is / 2 always.

        // declare these variables outside of loop and assembly scope
        // uint256 length;
        // uint256 newLength;
        // uint256 resultIndexPointer;
        // uint256 dataIndexPointer;
        // uint256 stopIteration;
        // bool hashLast;
        assembly {
            function hashLeafPairs(left, right) -> _hash {
                switch lt(left, right)
                case 0 {
                    mstore(0x0, right)
                    mstore(0x20, left)
                }
                default {
                    mstore(0x0, left)
                    mstore(0x20, right)
                }
                _hash := keccak256(0x0, 0x40)
            }
            // we will be modifying data in-place, so set result pointer to data pointer
            result := data
            // get length of original data array
            let length := mload(data)
            let newLength
            let hashLast

            switch and(length, 1)
            case 1 {
                // if length is odd, add 1 so division by 2 will round up
                newLength := add(1, div(length, 2))
                // note that we will need to hash the last element of data with 0 to get last element of result array
                hashLast := 1
            }
            default {
                newLength := div(length, 2)
            }
            mstore(data, newLength)
            let resultIndexPointer := add(0x20, data)
            let dataIndexPointer := resultIndexPointer
            // stop iterating over for loop at length-1
            let stopIteration := add(data, mul(length, 0x20))

            for {

            } lt(dataIndexPointer, stopIteration) {

            } {
                let data1 := mload(dataIndexPointer)
                let data2 := mload(add(dataIndexPointer, 0x20))
                let hashedPair := hashLeafPairs(data1, data2)
                mstore(resultIndexPointer, hashedPair)
                resultIndexPointer := add(0x20, resultIndexPointer)
                dataIndexPointer := add(0x40, dataIndexPointer)
            }

            if hashLast {
                let data1 := mload(dataIndexPointer)
                let hashedPair := hashLeafPairs(data1, 0)
                mstore(resultIndexPointer, hashedPair)
            }
        }
    }
}
