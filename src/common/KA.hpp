#ifndef KA_H
#define KA_H

#include <vector>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

namespace KA
{
std::vector<int> compute_shared_secret(EVP_PKEY *pkey, EVP_PKEY *peerkey) {//这里传入的是两个不同用户的密钥
    EVP_PKEY_CTX *ctx;
    //声明一个 unsigned char 类型的向量 secret_bytes，这个向量将用来存储生成的共享密钥的原始字节数据。
    std::vector<unsigned char> secret_bytes;
    //声明一个 int 类型的向量 secret，用于存储处理后的共享密钥数据。在这个特定的代码中，共享密钥将被转换为一个或多个整数，然后存储在这个向量中。
    std::vector<int> secret;
    //声明一个 size_t 类型的变量 secret_len，用来存储密钥派生函数生成的共享密钥的长度（以字节为单位）。这个长度是动态确定的，依赖于使用的密钥协议和公钥的类型。
    size_t secret_len;

    //创建一个 EVP_PKEY_CTX 对象，用于执行密钥派生操作。这个对象将包含密钥和密钥派生函数的参数。
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        std::cerr << "EVP_PKEY_CTX_new failed" << std::endl;
        return {};
    }
// 初始化密钥派生操作
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        std::cerr << "EVP_PKEY_derive_init failed" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return {};
    }
    
    // 设置对等方公钥，将对方的公钥 peerkey 设置到派生上下文中。
    //这一步是密钥协商中的一个重要部分，确保了两个公钥能够用于生成共享密钥。如果设置失败，同样会清理资源并返回。
    if (EVP_PKEY_derive_set_peer(ctx, peerkey) <= 0) {
        std::cerr << "EVP_PKEY_derive_set_peer failed" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return {};
    }
// 获取密钥派生函数生成的共享密钥的长度
//传入 NULL 作为第一个参数，用来获取必要的缓冲区长度 (secret_len)。这是为了准备足够的空间存储即将生成的共享密钥。
    if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0) {
        std::cerr << "EVP_PKEY_derive failed to determine buffer length" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return {};
    }
//生成共享密钥
//调整 secret_bytes 的大小以匹配预计的长度 (secret_len)，然后再次调用 EVP_PKEY_derive，这次是为了实际生成密钥，并将其存储到 secret_bytes 中。
    secret_bytes.resize(secret_len);
    if (EVP_PKEY_derive(ctx, secret_bytes.data(), &secret_len) <= 0) {
        std::cerr << "EVP_PKEY_derive failed" << std::endl;
        secret_bytes.clear();
    }

    EVP_PKEY_CTX_free(ctx);
    
    // 简单处理：将密钥转换为整数并返回共享密钥
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