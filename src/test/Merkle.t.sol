// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import "../Merkle.sol";
import "forge-std/Test.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/MerkleProof.sol";
import {Util} from "./Util.sol";

contract MerkleTest is Test {
    Merkle m;

    function setUp() public {
        m = new Merkle(true);
    }

    function testHashes(bytes32 left, bytes32 right) public {
        bytes32 hAssem = m.hashLeafPairs(left, right);
        bytes memory packed;
        if (left <= right) {
            packed = abi.encodePacked(left, right);
        } else {
            packed = abi.encodePacked(right, left);
        }
        bytes32 hNaive = keccak256(packed);
        assertEq(hAssem, hNaive);
    }

    function testGenerateProof(bytes32[] memory data, uint256 node) public {
        vm.assume(data.length > 1);
        node = bound(node, 0, data.length - 1);

        bytes32 root = m.getRoot(data);
        bytes32[] memory proof = m.getProof(data, node);

        assertEq(proof.length, Util.log2ceilBitMagic(data.length));

        bytes32 valueToProve = data[node];

        bytes32 rollingHash = valueToProve;
        for (uint256 i = 0; i < proof.length; ++i) {
            rollingHash = m.hashLeafPairs(rollingHash, proof[i]);
        }
        assertEq(rollingHash, root);
    }

    function testVerifyProof(bytes32[] memory data, uint256 node) public {
        vm.assume(data.length > 1);
        vm.assume(node < data.length);
        bytes32 root = m.getRoot(data);
        bytes32[] memory proof = m.getProof(data, node);
        bytes32 valueToProve = data[node];
        assertTrue(m.verifyProof(root, proof, valueToProve));
    }

    function testFailVerifyProof(
        bytes32[] memory data,
        bytes32 valueToProve,
        uint256 node
    ) public {
        vm.assume(data.length > 1);
        vm.assume(node < data.length);
        vm.assume(valueNotInArray(data, valueToProve));
        bytes32 root = m.getRoot(data);
        bytes32[] memory proof = m.getProof(data, node);
        assertTrue(m.verifyProof(root, proof, valueToProve));
    }

    function testVerifyProofOzForGasComparison(
        bytes32[] memory data,
        uint256 node
    ) public {
        vm.assume(data.length > 1);
        vm.assume(node < data.length);
        bytes32 root = m.getRoot(data);
        bytes32[] memory proof = m.getProof(data, node);
        bytes32 valueToProve = data[node];
        assertTrue(MerkleProof.verify(proof, root, valueToProve));
    }

    function testWontGetRootSingleLeaf() public {
        bytes32[] memory data = new bytes32[](1);
        data[0] = bytes32(0x0);
        vm.expectRevert("won't generate root for single leaf");
        m.getRoot(data);
    }

    function testWontGetProofSingleLeaf() public {
        bytes32[] memory data = new bytes32[](1);
        data[0] = bytes32(0x0);
        vm.expectRevert("won't generate proof for single leaf");
        m.getProof(data, 0x0);
    }

    function valueNotInArray(bytes32[] memory data, bytes32 value)
        public
        pure
        returns (bool)
    {
        for (uint256 i = 0; i < data.length; ++i) {
            if (data[i] == value) return false;
        }
        return true;
    }

    function testBadProof() public {
        m = new Merkle(false);

        uint8[5] memory unhashedElements = [0, 2, 4, 1, 3];
        bytes32[] memory hashedElements = new bytes32[](5);
        for (uint256 i = 0; i < 5; ++i) {
            hashedElements[i] = keccak256(abi.encode(unhashedElements[i]));
        }

        bytes32[5] memory expectedHashedLeaves = [
            bytes32(
                0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563
            ),
            bytes32(
                0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace
            ),
            bytes32(
                0x8a35acfbc15ff81a39ae7d344fd709f28e8600b4aa8c65c6b64bfe7fe36bd19b
            ),
            bytes32(
                0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6
            ),
            bytes32(
                0xc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b
            )
        ];
        for (uint256 i = 0; i < 5; ++i) {
            assertEq(hashedElements[i], expectedHashedLeaves[i]);
        }

        bytes32[] memory expectedProof = new bytes32[](3);
        expectedProof[
            0
        ] = 0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace;
        expectedProof[
            1
        ] = 0xb4ac32458d01ec09d972c820893c530c5aca86752a8c02e2499f60b968613ded;
        expectedProof[
            2
        ] = 0xc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b;
        bytes32[] memory generatedProof = m.getProof(hashedElements, 0);
        for (uint256 i = 0; i < 3; ++i) {
            assertEq(generatedProof[i], expectedProof[i]);
        }

        assertEq(
            m.getRoot(hashedElements),
            0x91bcc50c5289d8945a178a27e28c83c68df8043d45285db1eddc140f73ac2c83
        );
    }
}
