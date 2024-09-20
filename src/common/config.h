
namespace ENCRYPTO {

struct PsiAnalyticsContext {
  uint16_t port;
  uint32_t role;
  uint64_t bitlen;
  // uint64_t neles;
  uint64_t cneles;
  uint64_t sneles;
  // uint64_t serverneles;
  uint64_t nbins;
  uint64_t cnbins;
  uint64_t snbins;
  uint64_t nfuns;  // number of hash functions in the hash table
  uint64_t radix;
  double epsilon;
  uint64_t ffuns;
  // uint64_t fbins;
  double fepsilon;
  std::string address;

  std::vector<uint64_t> sci_io_start;
  uint64_t index;
  uint64_t n;
  uint64_t g;

  uint64_t sentBytesOPRF;
  uint64_t recvBytesOPRF;
  uint64_t sentBytesHint;
  uint64_t recvBytesHint;
  uint64_t sentBytesSCI;
  uint64_t recvBytesSCI;

  uint64_t sentBytes;
  uint64_t recvBytes;

  enum {
    PSM1,
    PSM2,
    PSM3
  } psm_type;

  struct {
    double vrf;
    // double hashing;
    double base_ots_sci;
    double base_ots_libote;
    double oprf1;
    double oprf2;
    double hint_transmission;
    double hint_computation;
    double encrypt;
    double decrypt;
    double psm;
    double total;
    double totalWithoutOT;
    double search;
    double wholeoprf;
    double addtime;
  } timings;
};

}
