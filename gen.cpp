// gen.cpp — standalone generator for container compatible with decryptContainer()
// Build: g++ -std=c++17 gen.cpp -o gen -lssl -lcrypto -lsodium

#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <cstring>
#include <cstdint>

// normalize: trim, collapse whitespace, lowercase (same logic as in Qt code)
static std::string normalize(const std::string &s) {
    size_t i = 0, j = s.size();
    while (i < j && std::isspace((unsigned char)s[i])) ++i;
    while (j > i && std::isspace((unsigned char)s[j-1])) --j;
    std::string tmp;
    tmp.reserve(j - i);
    bool in_space = false;
    for (size_t k = i; k < j; ++k) {
        unsigned char c = s[k];
        if (std::isspace(c)) {
            if (!in_space) {
                tmp.push_back(' ');
                in_space = true;
            }
        } else {
            tmp.push_back(std::tolower(c));
            in_space = false;
        }
    }
    return tmp;
}

static void append_le32(std::vector<unsigned char> &v, uint32_t x) {
    v.push_back((unsigned char)(x & 0xff));
    v.push_back((unsigned char)((x >> 8) & 0xff));
    v.push_back((unsigned char)((x >> 16) & 0xff));
    v.push_back((unsigned char)((x >> 24) & 0xff));
}

int main(int argc, char **argv) {
    // Parameters (must match decryptContainer expectations)
    const std::string password_in = "i love you";
    const std::string plaintext = "i love you too";

    const uint32_t mem_mb = 256;   // will be stored in header
    const uint32_t opslimit = 3;   // will be stored in header
    const uint32_t salt_len = 16;
    const uint32_t iv_len = 12;
    const uint8_t kdf_id = 1; // argon2id

    if (sodium_init() < 0) {
        std::cerr << "sodium_init failed\n";
        return 1;
    }

    // normalize password same as runtime
    std::string pass_norm = normalize(password_in);

    // generate salt
    std::vector<unsigned char> salt(salt_len);
    randombytes_buf(salt.data(), salt_len);

    // derive key using libsodium crypto_pwhash
    std::vector<unsigned char> key(32);
    unsigned long long memlimit = (unsigned long long)mem_mb * 1024ULL * 1024ULL;

    int rc = crypto_pwhash(
        key.data(), key.size(),
        pass_norm.c_str(), (unsigned long long)pass_norm.size(),
        salt.data(),
        (unsigned long long)opslimit,
        (size_t)memlimit,
        crypto_pwhash_ALG_ARGON2ID13
        );
    if (rc != 0) {
        std::cerr << "crypto_pwhash failed\n";
        return 1;
    }

    // generate IV
    std::vector<unsigned char> iv(iv_len);
    if (RAND_bytes(iv.data(), iv_len) != 1) {
        std::cerr << "RAND_bytes failed\n";
        return 1;
    }

    // AES-256-GCM encrypt
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { std::cerr << "EVP_CIPHER_CTX_new failed\n"; return 1; }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key.data(), iv.data())) {
        std::cerr << "EVP_EncryptInit_ex failed\n"; EVP_CIPHER_CTX_free(ctx); return 1;
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + 16);
    int outlen = 0;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen,
                               reinterpret_cast<const unsigned char*>(plaintext.data()),
                               (int)plaintext.size())) {
        std::cerr << "EVP_EncryptUpdate failed\n"; EVP_CIPHER_CTX_free(ctx); return 1;
    }
    int cipher_len = outlen;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &outlen)) {
        std::cerr << "EVP_EncryptFinal_ex failed\n"; EVP_CIPHER_CTX_free(ctx); return 1;
    }
    cipher_len += outlen;
    ciphertext.resize(cipher_len);

    unsigned char tag[16];
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
        std::cerr << "EVP_CIPHER_CTX_ctrl(GET_TAG) failed\n"; EVP_CIPHER_CTX_free(ctx); return 1;
    }
    EVP_CIPHER_CTX_free(ctx);

    // build container: header + salt + iv + ciphertext + tag
    std::vector<unsigned char> out;
    // magic 8 bytes
    const char magic[8] = {'M','Y','A','P','P','v','1','\0'};
    out.insert(out.end(), magic, magic+8);
    // kdf id
    out.push_back(kdf_id);
    // mem_mb (4 bytes LE)
    append_le32(out, mem_mb);
    // opslimit
    append_le32(out, opslimit);
    // salt_len
    append_le32(out, salt_len);
    // ct_len
    append_le32(out, (uint32_t)ciphertext.size());
    // payload
    out.insert(out.end(), salt.begin(), salt.end());
    out.insert(out.end(), iv.begin(), iv.end());
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    out.insert(out.end(), tag, tag + 16);

    // print C array
    std::cout << "/* Paste this array into Sources/crypto.cpp (replace old kContainer[]) */\n";
    std::cout << "static const unsigned char kContainer[] = {\n";
    for (size_t i = 0; i < out.size(); ++i) {
        std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0')
                  << (int)out[i];
        if (i + 1 != out.size()) std::cout << ", ";
        if ((i + 1) % 12 == 0) std::cout << "\n";
    }
    std::cout << "\n};\n";
    std::cout << "const size_t kContainerSize = " << std::dec << out.size() << ";\n\n";

    std::cout << "/* password used (normalized): \"" << pass_norm << "\" */\n";
    std::cout << "/* plaintext: \"" << plaintext << "\" */\n";
    return 0;
}
