// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

abstract contract MurkyBase {
    bool immutable HASH_ODD_WITH_ZERO;

    constructor(bool hashOddWithZero) {
        HASH_ODD_WITH_ZERO = hashOddWithZero;
    }

    /********************
     * VIRTUAL HASHING FUNCTIONS *
     ********************/
    function hashLeafPairs(bytes32 left, bytes32 right)
        public
        pure
        virtual
        returns (bytes32 _hash);

    /**********************
     * PROOF VERIFICATION *
     **********************/

    function verifyProof(
        bytes32 root,
        bytes32[] calldata proof,
        bytes32 valueToProve
    ) external pure returns (bool) {
        // proof length must be less than max array size
        bytes32 rollingHash = valueToProve;
        uint256 length = proof.length;
        unchecked {
            for (uint256 i = 0; i < length; ++i) {
                rollingHash = hashLeafPairs(rollingHash, proof[i]);
            }
        }
        return root == rollingHash;
    }

    /********************
     * PROOF GENERATION *
     ********************/

    function getRoot(bytes32[] memory data) external virtual returns (bytes32);

    function getProof(bytes32[] memory data, uint256 node)
        external
        virtual
        returns (bytes32[] memory result);
}
