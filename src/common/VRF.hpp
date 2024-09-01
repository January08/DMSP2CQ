#ifndef VRF_H
#define VRF_H

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <vector>
#include <iomanip>

class VRF {
 private:
  struct Node {
    size_t id;
    std::string signature;
    std::string timestamp;  // 存储时间戳用于验证
    int hash_value;
    EVP_PKEY *public_key;
    bool verify_result;  // 存储签名验证结果
  };

 public:
  VRF() { OpenSSL_add_all_algorithms(); }

  std::vector<size_t> sequence(size_t n = 10) {
    std::vector<Node> nodes(n);

    for (int i = 0; i < n; ++i) {
      nodes[i].id = i;

      EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
      EVP_PKEY_keygen_init(pctx);
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp256k1);
      EVP_PKEY *pkey = NULL;
      EVP_PKEY_keygen(pctx, &pkey);
      nodes[i].public_key = pkey;

      nodes[i].timestamp = std::to_string(std::time(0));  // 使用时间戳作为消息

      EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
      unsigned char sig[256];
      unsigned int sig_len;
      EVP_SignInit(mdctx, EVP_sha256());
      EVP_SignUpdate(mdctx, nodes[i].timestamp.c_str(), nodes[i].timestamp.size());
      EVP_SignFinal(mdctx, sig, &sig_len, pkey);
      nodes[i].signature = to_hex(sig, sig_len);

      nodes[i].hash_value = hash_signature(nodes[i].signature);

      // 验证签名
      EVP_MD_CTX *vctx = EVP_MD_CTX_new();
      EVP_VerifyInit(vctx, EVP_sha256());
      EVP_VerifyUpdate(vctx, nodes[i].timestamp.c_str(), nodes[i].timestamp.size());
      nodes[i].verify_result = (EVP_VerifyFinal(vctx, sig, sig_len, pkey) == 1);
      EVP_MD_CTX_free(vctx);

      EVP_MD_CTX_free(mdctx);
      EVP_PKEY_CTX_free(pctx);
    }

    std::sort(nodes.begin(), nodes.end(),
              [=](const Node &a, const Node &b) { return a.hash_value < b.hash_value; });

    std::vector<size_t> seq;

    for (size_t i = 0; i < n; i++) seq.push_back(nodes[i].id);

    // // 输出排序后的节点信息
    // for (const auto &node : nodes)
    // {
    //     std::cout << node.id << ": Signature = " << node.signature
    //             << ", Hash = " << node.hash_value;
    //     if (node.verify_result)
    //     {
    //         std::cout << " (Signature Verification Passed)";
    //     }
    //     else
    //     {
    //         std::cout << " (Signature Verification Failed)";
    //     }
    //     std::cout << std::endl;
    // }

    EVP_cleanup();

    return seq;
  }

 private:
  std::string to_hex(const unsigned char *data, size_t length) {
    std::stringstream hex_stream;
    hex_stream << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
      hex_stream << std::setw(2) << static_cast<int>(data[i]);
    }
    return hex_stream.str();
  }

  int hash_signature(const std::string &sig) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, sig.data(), sig.size());
    EVP_DigestFinal_ex(mdctx, hash, &lengthOfHash);
    EVP_MD_CTX_free(mdctx);

    int hash_value = 0;
    for (unsigned int i = 0; i < lengthOfHash; ++i) {
      hash_value = (hash_value + hash[i]) % 100 + 1;
    }
    return hash_value;
  }
};

#endif