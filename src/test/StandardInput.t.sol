pragma solidity ^0.8.4;

import "../Xorkle.sol";
import "../Merkle.sol";
import "forge-std/Test.sol";

contract StandardizedInputTest is Test {
    Xorkle x;
    Merkle m;
    bytes32[100] data;
    uint256[8] leaves = [4, 8, 15, 16, 23, 42, 69, 88];

    function setUp() public {
        string[] memory inputs = new string[](2);
        inputs[0] = "cat";
        inputs[1] = "src/test/standard_data/StandardInput.txt";
        bytes memory result = vm.ffi(inputs);
        data = abi.decode(result, (bytes32[100]));
        x = new Xorkle(true);
        m = new Merkle(true);
    }

    function testXorkleGenerateProofStandard() public view {
        Xorkle _x = x;
        bytes32[] memory _data = _getData();
        uint256[] memory _leaves = _getLeaves();
        uint256 leavesLength = _leaves.length;
        for (uint256 i = 0; i < leavesLength; ++i) {
            _x.getProof(_data, _leaves[i]);
        }
    }

    function testMerkleGenerateProofStandard() public view {
        Merkle _m = m;
        bytes32[] memory _data = _getData();
        uint256[] memory _leaves = _getLeaves();
        uint256 leavesLength = _leaves.length;

        for (uint256 i = 0; i < leavesLength; ++i) {
            _m.getProof(_data, _leaves[i]);
        }
    }

    function testXorkleVerifyProofStandard() public {
        Xorkle _x = x;
        bytes32[] memory _data = _getData();
        uint256[] memory _leaves = _getLeaves();
        bytes32 root = _x.getRoot(_data);
        uint256 leavesLength = _leaves.length;
        for (uint256 i = 0; i < leavesLength; ++i) {
            bytes32[] memory proof = x.getProof(_data, _leaves[i]);
            assertTrue(_x.verifyProof(root, proof, _data[_leaves[i]]));
        }
    }

    function testMerkleVerifyProofStandard() public {
        Merkle _m = m;
        bytes32[] memory _data = _getData();
        uint256[] memory _leaves = _getLeaves();
        bytes32 root = _m.getRoot(_data);
        uint256 leavesLength = _leaves.length;
        for (uint256 i = 0; i < leavesLength; ++i) {
            bytes32[] memory proof = _m.getProof(_data, _leaves[i]);
            assertTrue(_m.verifyProof(root, proof, _data[_leaves[i]]));
        }
    }

    function testStandardRetrievalGasReference() public view {
        Merkle _m = m;
        bytes32[] memory _data = _getData();
        uint256[] memory _leaves = _getLeaves();
    }

    function _getData() public view returns (bytes32[] memory) {
        bytes32[] memory _data = new bytes32[](data.length);
        uint256 length = data.length;
        for (uint256 i = 0; i < length; ++i) {
            _data[i] = data[i];
        }
        return _data;
    }

    function _getLeaves() public view returns (uint256[] memory) {
        uint256[] memory _leaves = new uint256[](leaves.length);
        uint256 length = leaves.length;
        for (uint256 i = 0; i < length; ++i) {
            _leaves[i] = leaves[i];
        }
        return _leaves;
    }
}
