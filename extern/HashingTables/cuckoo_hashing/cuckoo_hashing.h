

#include "common/hashing.h"

namespace ENCRYPTO {

class HashTableEntry;

class CuckooTable : public HashingTable {
 public:
  CuckooTable() = delete;

  CuckooTable(double epsilon) : CuckooTable(epsilon, 0, 0){};

  CuckooTable(double epsilon, std::size_t seed) : CuckooTable(epsilon, 0, seed){};

  CuckooTable(std::size_t num_of_bins) : CuckooTable(0.0f, num_of_bins, 0){};

  CuckooTable(std::size_t num_of_bins, std::size_t seed) : CuckooTable(0.0f, num_of_bins, seed){};

  ~CuckooTable() final{};

  bool Insert(std::uint64_t element) final;

  bool Insert(const std::vector<std::uint64_t>& elements) final;

  void SetRecursiveInsertionLimiter(std::size_t limiter);

  bool Print() const final;

  auto GetStatistics() const { return statistics_; }

  auto GetStashSize() const { return stash_.size(); }

  std::vector<uint64_t> AsRawVector() const final;

  std::vector<std::size_t> GetNumOfElementsInBins() const final;

 private:
  std::vector<HashTableEntry> hash_table_, stash_;
  std::size_t recursion_limiter_ = 200;

  struct Statistics {
    std::size_t recursive_remappings_counter_ = 0;
  } statistics_;

  CuckooTable(double epsilon, std::size_t num_of_bins, std::size_t seed);

  bool AllocateTable() final;

  bool MapElementsToTable() final;
};
}
