#ifndef UNUSE_H
#define UNUSE_H

#include "ENCRYPTO_utils/connection.h"
#include "ENCRYPTO_utils/socket.h"
#include "abycore/sharing/boolsharing.h"
#include "abycore/sharing/sharing.h"

#include "HashingTables/cuckoo_hashing/cuckoo_hashing.h"
#include "HashingTables/common/hash_table_entry.h"
#include "HashingTables/common/hashing.h"
#include "HashingTables/simple_hashing/simple_hashing.h"

uint64_t firstBlock(const osuCrypto::block& b)
{
  // 将 __m128i 类型的值强制转换为 u64 类型数组
  uint64_t values[2];
  _mm_storeu_si128((__m128i*)values, b);
  return values[0];
}

uint64_t secondBlock(const osuCrypto::block& b)
{
  // 将 __m128i 类型的值强制转换为 u64 类型数组
  uint64_t values[2];
  _mm_storeu_si128((__m128i*)values, b);
  return values[1];
}

std::vector<osuCrypto::block> toBlock(const std::vector<uint64_t>& vec)
{
  std::vector<osuCrypto::block> blocks;
  
  for(const auto&i : vec)
    blocks.push_back(osuCrypto::toBlock(i));

  return blocks;
}

std::vector<std::vector<osuCrypto::block>> toBlock(const std::vector<std::vector<uint64_t>>& vec)
{
  std::vector<std::vector<osuCrypto::block>> blocks;
  
  for(const auto&i : vec)
  {
    blocks.push_back(toBlock(i));
  }
    
  return blocks;
}

std::vector<uint64_t> toVec(const std::vector<osuCrypto::block>& blocks)
{
  std::vector<uint64_t> vec;
  
  for(const auto&i : blocks)
    vec.push_back(firstBlock(i));

  return vec;
}

std::vector<std::vector<uint64_t>> toVec(const std::vector<std::vector<osuCrypto::block>>& blocks)
{
  std::vector<std::vector<uint64_t>> vec(blocks.size());
  
  for(int i=0;i<blocks.size();i++)
  {
    vec[i].reserve(blocks[i].size());
    for(int j=0;j<blocks[i].size();j++)
      vec[i][j]=firstBlock(blocks[i][j]);
  }

  return vec;
}

#endif