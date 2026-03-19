#pragma once
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <vector>
#include <string>
#include <cstring>

// Hash R || Y || nonce
BIGNUM* hash_to_bn(EC_GROUP* group, EC_POINT* R, EC_POINT* Y, const std::string& nonce) {
    BN_CTX* ctx = BN_CTX_new();

    unsigned char buf[1024];
    size_t len = 0;

    len += EC_POINT_point2oct(group, R, POINT_CONVERSION_UNCOMPRESSED,
                              buf + len, sizeof(buf)-len, ctx);

    len += EC_POINT_point2oct(group, Y, POINT_CONVERSION_UNCOMPRESSED,
                              buf + len, sizeof(buf)-len, ctx);

    memcpy(buf + len, nonce.data(), nonce.size());
    len += nonce.size();

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(buf, len, hash);

    BN_CTX_free(ctx);
    return BN_bin2bn(hash, SHA256_DIGEST_LENGTH, NULL);
}

// PBKDF2
void derive_key(unsigned char* key, BIGNUM* x) {
    unsigned char buf[256];
    int len = BN_bn2bin(x, buf);

    PKCS5_PBKDF2_HMAC((char*)buf, len,
        (unsigned char*)"zk_salt", 7,
        10000,
        EVP_sha256(),
        32, key);
}

// AES-GCM Encrypt
std::vector<unsigned char> aes_encrypt(
    const std::vector<unsigned char>& plaintext,
    unsigned char* key,
    unsigned char* iv,
    unsigned char* tag) {

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> ciphertext(plaintext.size());

    int len;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                      plaintext.data(), plaintext.size());

    int ct_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext.data()+len, &len);
    ct_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(ct_len);
    return ciphertext;
}
