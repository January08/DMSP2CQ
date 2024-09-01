#ifndef BLOCK_H
#define BLOCK_H

#include <vector>
#include "HashingTables/simple_hashing/simple_hashing.h"

// 将 block 数据异或转化为 uint64_t
inline std::vector<uint64_t> blockToUint64Xor(const osuCrypto::block& b) {
  // 提取 block 的低64位和高64位
  uint64_t low = _mm_extract_epi64(b, 0);
  uint64_t high = _mm_extract_epi64(b, 1);

  // 计算高64位和低64位的异或
  uint64_t xor_result = high ^ low;

  // 返回包含异或结果的向量
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