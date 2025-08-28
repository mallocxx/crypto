#pragma once
#include <QByteArray>
#include <QString>
#include <cstdint>

#pragma pack(push, 1)
struct Header {
    char     magic[8];
    uint8_t  kdf_id;
    uint32_t mem_mb;
    uint32_t opslimit;
    uint32_t salt_len;
    uint32_t ct_len;
};
#pragma pack(pop)

static constexpr int GCM_IV_LEN  = 12;
static constexpr int GCM_TAG_LEN = 16;
static constexpr uint8_t KDF_ID_ARGON2ID = 1;

QByteArray normalize(const QString &s);

bool deriveKey_Argon2id(const QByteArray &pass,
                        const unsigned char *salt, size_t salt_len,
                        uint32_t mem_mb, uint32_t opslimit,
                        QByteArray &outKey);

QByteArray decryptContainer(const QByteArray &container,
                            const QByteArray &passwordUtf8);

extern const unsigned char kContainer[];
extern const size_t kContainerSize;
