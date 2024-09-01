#ifndef PAILLIER_H
#define PAILLER_H

#include <NTL/ZZ.h>

namespace Paillier {

static NTL::ZZ L_function(const NTL::ZZ &x, const NTL::ZZ &n) { return (x - 1) / n; }

NTL::ZZ encryptNumber(const NTL::ZZ &m, const NTL::ZZ &n, const NTL::ZZ &g) {
  NTL::ZZ r = RandomBnd(n);
  NTL::ZZ c = (PowerMod(g, m, n * n) * PowerMod(r, n, n * n)) % (n * n);
  return c;
}

static void keyGeneration(NTL::ZZ &p, NTL::ZZ &q, NTL::ZZ &n, NTL::ZZ &phi, NTL::ZZ &lambda,
                          NTL::ZZ &g, NTL::ZZ &lambdaInverse, const long &k, NTL::ZZ &r) {
  // GenPrime(p, k);
  // GenPrime(q, k);
  p = NTL:: conv<NTL::ZZ>("170369836905864867684309212653434262426987938535888948303343979225024835886168078093796818886592237348510637694670620820366525714457605719170269197764594241739848193424434938416550394419857471465453775845544086337932975312352204971593851342578781185058634405681854702110933438192294613993510873668567928731243");
  q = NTL:: conv<NTL::ZZ>("149768149729033307895505028003794196818268474299954831138524826553669917000883960981312528977336320600301799133665793752383828006419796280219516217446131872011208294375626716112087760647019520809744249184210808530036172164648089977300270273261641176103449053170269377444096575049406585536331422165063744966029");
  n = p * q;
  phi = (p - 1) * (q - 1);
  lambda = phi / GCD(p - 1, q - 1);
  lambdaInverse = InvMod(lambda, n);
  g = n + 1;
  r = RandomBnd(n);
  // std::cout << "KeyGeneration Completed" << endl;
}

NTL::ZZ decryptNumber(const NTL::ZZ &c, const NTL::ZZ &n, const NTL::ZZ &lambda,
                      const NTL::ZZ &lambdaInverse) {
  NTL::ZZ m = (L_function(PowerMod(c, lambda, n * n), n) * lambdaInverse) % n;
  // std::cout << "The decrypted result: " << m << endl;
  return m;
}

std::vector<NTL::ZZ> encrypt(const std::vector<NTL::ZZ> &numbers, const NTL::ZZ &n,
                             const NTL::ZZ &g) {
  std::vector<NTL::ZZ> encrypted_numbers;
  for (const NTL::ZZ &num : numbers) {
    NTL::ZZ encrypted_num = encryptNumber(num, n, g);
    encrypted_numbers.push_back(encrypted_num);
  }
  return encrypted_numbers;
}

std::vector<NTL::ZZ> numbers(size_t n = 8) {
  std::vector<NTL::ZZ> nums;
  for (int i = 0; i < n; ++i) {
    NTL::ZZ random_num =
        RandomBnd(NTL::ZZ(10000)) + 1;  // Generate random number between 1 and 100
    nums.push_back(random_num);
  }
  return nums;
}

class Paillier {
 private:
  NTL::ZZ p, q, n, phi, lambda, g, lambdaInverse, r;
  long bit_length;  // Bit length for the prime numbers p and q

 public:
  Paillier(long bit_len = 1024) : bit_length(bit_len) {
    // Initialize random number generation
    srand(time(NULL));

    // Generate keys
    keyGeneration(p, q, n, phi, lambda, g, lambdaInverse, bit_length, r);
  }

  NTL::ZZ getN() { return n; }
  NTL::ZZ getG() { return g; }
  NTL::ZZ getLambda() { return lambda; }
  NTL::ZZ getLambdaInverse() { return lambdaInverse; }

 private:
  static NTL::ZZ EncryptedSum(const std::vector<NTL::ZZ> &values, const NTL::ZZ &n,
                              const NTL::ZZ &g) {
    NTL::ZZ encrypted_sum = encryptNumber(NTL::ZZ(0), n, g);
    for (const NTL::ZZ &val : values) {
      NTL::ZZ encrypted_val = encryptNumber(val, n, g);
      encrypted_sum = (encrypted_sum * encrypted_val) % (n * n);
    }
    return encrypted_sum;
  }
};

}  // namespace Paillier

#endif