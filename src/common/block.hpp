#ifndef BLOCK_H
#define BLOCK_H

#include <vector>
#include "HashingTables/simple_hashing/simple_hashing.h"

inline std::vector<uint64_t> blockToUint64Xor(const osuCrypto::block& b) {
  uint64_t low = _mm_extract_epi64(b, 0);
  uint64_t high = _mm_extract_epi64(b, 1);

  uint64_t xor_result = high ^ low;
  return std::vector<uint64_t>{xor_result};
}

inline std::string blockToHex(const osuCrypto::block& blk) {
  std::stringstream ss;
  const uint8_t* data = reinterpret_cast<const uint8_t*>(&blk);
  ss << std::hex << std::setfill('0');
  for (size_t i = 0; i < sizeof(osuCrypto::block); ++i) {
    ss << std::setw(2) << (data[i] & 0xFF);
  }
  return ss.str();
}

#endif
