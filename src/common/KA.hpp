#ifndef KA_H
#define KA_H

#include <vector>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

namespace KA
{
std::vector<int> compute_shared_secret(EVP_PKEY *pkey, EVP_PKEY *peerkey) {
    EVP_PKEY_CTX *ctx;
   
    std::vector<unsigned char> secret_bytes;
    std::vector<int> secret;
    size_t secret_len;

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        std::cerr << "EVP_PKEY_CTX_new failed" << std::endl;
        return {};
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        std::cerr << "EVP_PKEY_derive_init failed" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return {};
    }
    

    if (EVP_PKEY_derive_set_peer(ctx, peerkey) <= 0) {
        std::cerr << "EVP_PKEY_derive_set_peer failed" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0) {
        std::cerr << "EVP_PKEY_derive failed to determine buffer length" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return {};
    }
    secret_bytes.resize(secret_len);
    if (EVP_PKEY_derive(ctx, secret_bytes.data(), &secret_len) <= 0) {
        std::cerr << "EVP_PKEY_derive failed" << std::endl;
        secret_bytes.clear();
    }

    EVP_PKEY_CTX_free(ctx);
    
    int key_as_int = 0;
    for (auto byte : secret_bytes) {
        key_as_int = (key_as_int << 8) | byte;
    }
    secret.push_back(key_as_int);

    return secret;
}

static EVP_PKEY* generate_key(EVP_PKEY *params) {
    EVP_PKEY *key = nullptr;
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(params, NULL);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_keygen(kctx, &key);
    EVP_PKEY_CTX_free(kctx);
    return key;
}

class KA
{
    private:
        EVP_PKEY* m_Params;
        EVP_PKEY_CTX* m_Pctx;
        EVP_PKEY* m_Key;

    public:
        KA(): m_Key(nullptr)
        {
            m_Params=EVP_PKEY_new();
            m_Pctx=EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
            EVP_PKEY_paramgen_init(m_Pctx);
            EVP_PKEY_CTX_set_dh_paramgen_prime_len(m_Pctx, 1024);
            EVP_PKEY_paramgen(m_Pctx, &m_Params);
        }

        ~KA()
        {
            EVP_PKEY_free(m_Params);
            EVP_PKEY_CTX_free(m_Pctx);

            if(m_Key!=nullptr)
                EVP_PKEY_free(m_Key);
        }

        EVP_PKEY* key(bool createNew=false)
        {
            EVP_PKEY* tmp_key;
            if(m_Key==nullptr||createNew)
            {
                tmp_key=generate_key(m_Params);

                if(createNew)
                    return tmp_key;
                else
                    m_Key=tmp_key;
            }
            
            return m_Key;
        }

        std::vector<EVP_PKEY*> keys(size_t n)
        {
            std::vector<EVP_PKEY*> vec(n);

            for(int i=0;i<n;i++)
            {
                vec[i]=key(true);
            }
                
            
            return vec;
        }
};

}

#endif
