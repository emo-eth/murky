// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

library Util {
  uint136 constant _2_128 = 2**128;
  uint72 constant _2_64 = 2**64;
  uint40 constant _2_32 = 2**32;
  uint24 constant _2_16 = 2**16;
  uint16 constant _2_8 = 2**8;
  uint8 constant _2_4 = 2**4;
  uint8 constant _2_2 = 2**2;
  uint8 constant _2_1 = 2**1;

  /// Original bitmagic adapted from https://github.com/paulrberg/prb-math/blob/main/contracts/PRBMath.sol
  /// @dev Note that x assumed > 1
  function log2ceilBitMagic(uint256 x)
    public
    pure
    returns (uint256 mostSignificantBit)
  {
    /// @solidity memory-safe-assembly
    assembly {
      let xCopy := x
      if iszero(lt(x, _2_128)) {
        x := shr(128, x)
        mostSignificantBit := add(mostSignificantBit, 128)
      }
      if iszero(lt(x, _2_64)) {
        x := shr(64, x)
        mostSignificantBit := add(mostSignificantBit, 64)
      }
      if iszero(lt(x, _2_32)) {
        x := shr(32, x)
        mostSignificantBit := add(mostSignificantBit, 32)
      }
      if iszero(lt(x, _2_16)) {
        x := shr(16, x)
        mostSignificantBit := add(mostSignificantBit, 16)
      }
      if iszero(lt(x, _2_8)) {
        x := shr(8, x)
        mostSignificantBit := add(mostSignificantBit, 8)
      }
      if iszero(lt(x, _2_4)) {
        x := shr(4, x)
        mostSignificantBit := add(mostSignificantBit, 4)
      }
      if iszero(lt(x, _2_2)) {
        x := shr(2, x)
        mostSignificantBit := add(mostSignificantBit, 2)
      }
      if iszero(lt(x, _2_1)) {
        // No need to shift x any more.
        mostSignificantBit := add(mostSignificantBit, 1)
      }
      let lsb := and(add(1, not(xCopy)), xCopy)
      if and(iszero(eq(lsb, xCopy)), gt(xCopy, 0)) {
        mostSignificantBit := add(mostSignificantBit, 1)
      }
    }
  }
}
