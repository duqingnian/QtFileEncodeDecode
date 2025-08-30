
#pragma once
#include <cstdint>

namespace AppVer {
    static constexpr const char* kAppName = "QtZlibOpenSSLEncryptor";
    static constexpr const char* kMagic   = "QZAE1";     // 5 bytes
    static constexpr uint8_t     kVersion = 1;
    static constexpr uint8_t     kCipher  = 1;           // 1 = AES-256-GCM
    static constexpr uint32_t    kPBKDF2Iterations = 200000;
    static constexpr uint8_t     kSaltLen = 16;
    static constexpr uint8_t     kIVLen   = 12;          // GCM nonce 12 bytes
    static constexpr uint8_t     kTagLen  = 16;          // GCM tag 16 bytes
}
