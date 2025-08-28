#include "crypto.h"
#include <QRegularExpression>
#include <openssl/evp.h>
#include <sodium.h>
#include <cstring>

// ---------------------------------------------------------------------------
const unsigned char kContainer[] = {
    0x4d, 0x59, 0x41, 0x50, 0x50, 0x76, 0x31, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x00, 0x03, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00,
    0x00, 0x91, 0xb4, 0x5c, 0x4c, 0x37, 0x57, 0xbc, 0x95, 0xc3, 0xfe, 0x48,
    0x71, 0x85, 0xf4, 0x39, 0x87, 0x7c, 0x30, 0x12, 0xc0, 0x0f, 0x0b, 0x5a,
    0x8a, 0xb8, 0xc7, 0xef, 0x24, 0xc5, 0x0f, 0x61, 0x75, 0x36, 0x82, 0x69,
    0x4d, 0x50, 0x95, 0xb0, 0x5d, 0xb9, 0xa8, 0x96, 0x95, 0x73, 0x37, 0x3d,
    0xce, 0x8c, 0xc8, 0xb4, 0x30, 0x18, 0xbf, 0x1b, 0x91, 0xec, 0xef
};
const size_t kContainerSize = sizeof(kContainer);

// ---------------------------------------------------------------------------

QByteArray normalize(const QString &s) {
    return s.trimmed().toLower()
        .replace(QRegularExpression("\\s+"), " ")
        .toUtf8();
}

bool deriveKey_Argon2id(const QByteArray &pass,
                        const unsigned char *salt, size_t salt_len,
                        uint32_t mem_mb, uint32_t opslimit,
                        QByteArray &outKey)
{
    if (sodium_init() < 0) return false;

    unsigned long long memlimit = (unsigned long long)mem_mb * 1024ULL * 1024ULL;
    unsigned long long ops = opslimit;

    if (memlimit < 64ULL*1024ULL*1024ULL) memlimit = 64ULL*1024ULL*1024ULL;
    if (memlimit > 1024ULL*1024ULL*1024ULL) memlimit = 1024ULL*1024ULL*1024ULL;
    if (ops < 1) ops = 1; if (ops > 6) ops = 6;

    outKey.resize(32);
    int rc = crypto_pwhash(
        reinterpret_cast<unsigned char*>(outKey.data()), outKey.size(),
        pass.constData(), (unsigned long long)pass.size(),
        salt,
        ops,
        memlimit,
        crypto_pwhash_ALG_ARGON2ID13
        );
    return rc == 0;
}

QByteArray decryptContainer(const QByteArray &container,
                            const QByteArray &passwordUtf8)
{
    if (container.size() < (int)sizeof(Header)) return {};

    const Header *hdr = reinterpret_cast<const Header*>(container.constData());
    if (std::memcmp(hdr->magic, "MYAPPv1\0", 8) != 0) return {};
    if (hdr->kdf_id != KDF_ID_ARGON2ID) return {};

    size_t offset = sizeof(Header);
    if (container.size() < (int)(offset + hdr->salt_len + GCM_IV_LEN + hdr->ct_len + GCM_TAG_LEN)) return {};

    const unsigned char *salt = reinterpret_cast<const unsigned char*>(container.constData() + offset);
    offset += hdr->salt_len;
    const unsigned char *iv = reinterpret_cast<const unsigned char*>(container.constData() + offset);
    offset += GCM_IV_LEN;
    const unsigned char *ct = reinterpret_cast<const unsigned char*>(container.constData() + offset);
    offset += hdr->ct_len;
    const unsigned char *tag = reinterpret_cast<const unsigned char*>(container.constData() + offset);

    QByteArray key;
    if (!deriveKey_Argon2id(passwordUtf8, salt, hdr->salt_len, hdr->mem_mb, hdr->opslimit, key)) {
        return {};
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    QByteArray plaintext; plaintext.resize((int)hdr->ct_len);
    int len = 0, outLen = 0; bool ok = true;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                                reinterpret_cast<const unsigned char*>(key.constData()), iv)) ok = false;

    if (ok && 1 != EVP_DecryptUpdate(ctx,
                                     reinterpret_cast<unsigned char*>(plaintext.data()), &len,
                                     ct, (int)hdr->ct_len)) ok = false;

    outLen = len;

    if (ok && 1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                       GCM_TAG_LEN, const_cast<unsigned char*>(tag))) ok = false;

    if (ok && 1 != EVP_DecryptFinal_ex(ctx, nullptr, &len)) ok = false;

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) return {};
    plaintext.truncate(outLen);
    return plaintext;
}
