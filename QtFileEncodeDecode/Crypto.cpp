
#include "Crypto.h"
#include "ZlibStream.h"
#include "Version.h"

#include <QFile>
#include <QFileInfo>
#include <QByteArray>
#include <QDataStream>
#include <QSaveFile>
#include <QTemporaryFile>
#include <QDir>
#include <QScopeGuard>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <vector>
#include <array>
#include <cstring>
#include <stdexcept>
#include <memory>

namespace {

constexpr size_t IO_CHUNK = 1 << 20; // 1 MiB

struct Header {
    QByteArray magic;      // "QZAE1" (5 bytes)
    quint8     version;    // 1
    quint8     cipher;     // 1 = AES-256-GCM
    quint32    iterations; // PBKDF2 iterations
    quint8     saltLen;
    quint8     ivLen;
    quint8     tagLen;
    QByteArray salt;
    QByteArray iv;
};

QByteArray buildHeader(const Header& h) {
    QByteArray buf;
    QDataStream ds(&buf, QIODevice::WriteOnly);
    ds.setByteOrder(QDataStream::LittleEndian);
    ds.writeRawData(h.magic.constData(), h.magic.size());
    ds << h.version;
    ds << h.cipher;
    ds << h.iterations;
    ds << h.saltLen;
    ds << h.ivLen;
    ds << h.tagLen;
    ds.writeRawData(h.salt.constData(), h.salt.size());
    ds.writeRawData(h.iv.constData(), h.iv.size());
    return buf;
}

bool parseHeader(QFile& f, Header& h, QString& error) {
    // Read fixed part first
    const qint64 fixedSize = 5 + 1 + 1 + 4 + 1 + 1 + 1;
    QByteArray fixed = f.read(fixedSize);
    if (fixed.size() != fixedSize) {
        error = "读取文件头失败（长度不足）";
        return false;
    }
    QDataStream ds(fixed);
    ds.setByteOrder(QDataStream::LittleEndian);
    char magic[5];
    ds.readRawData(magic, 5);
    h.magic = QByteArray(magic, 5);
    if (h.magic != QByteArray(AppVer::kMagic, 5)) {
        error = "魔术头不匹配：这可能不是本程序生成的加密文件";
        return false;
    }
    ds >> h.version;
    ds >> h.cipher;
    ds >> h.iterations;
    ds >> h.saltLen;
    ds >> h.ivLen;
    ds >> h.tagLen;
    if (h.version != AppVer::kVersion || h.cipher != AppVer::kCipher) {
        error = "文件头版本或算法不受支持";
        return false;
    }
    // Read salt + iv
    QByteArray rest = f.read(h.saltLen + h.ivLen);
    if (rest.size() != (h.saltLen + h.ivLen)) {
        error = "读取文件头盐/IV失败";
        return false;
    }
    h.salt = rest.left(h.saltLen);
    h.iv   = rest.mid(h.saltLen, h.ivLen);
    return true;
}

bool deriveKey(const QString& password, const QByteArray& salt, uint32_t iters, std::array<unsigned char, 32>& keyOut, QString& error) {
    QByteArray passUtf8 = password.toUtf8();
    int ok = PKCS5_PBKDF2_HMAC(passUtf8.constData(), passUtf8.size(),
                               reinterpret_cast<const unsigned char*>(salt.constData()), salt.size(),
                               static_cast<int>(iters),
                               EVP_sha256(),
                               static_cast<int>(keyOut.size()),
                               keyOut.data());
    if (!ok) {
        error = "PBKDF2 派生密钥失败";
        return false;
    }
    return true;
}

QString opensslErr() {
    char buf[256]; buf[0] = 0;
    unsigned long e = ERR_get_error();
    if (e) ERR_error_string_n(e, buf, sizeof(buf));
    return QString::fromLatin1(buf);
}

} // namespace

bool encryptFileWithPassword(const QString& inPath, const QString& outPath, const QString& password,
                             const ProgressFn& progress, QString& errorMsg) {
    QFile in(inPath);
    if (!in.exists() || !in.open(QIODevice::ReadOnly)) {
        errorMsg = "无法打开输入文件：" + inPath;
        return false;
    }
    QSaveFile out(outPath);
    if (!out.open(QIODevice::WriteOnly)) {
        errorMsg = "无法打开输出文件：" + outPath;
        return false;
    }

    // Prepare header
    Header h;
    h.magic = QByteArray(AppVer::kMagic, 5);
    h.version = AppVer::kVersion;
    h.cipher = AppVer::kCipher;
    h.iterations = AppVer::kPBKDF2Iterations;
    h.saltLen = AppVer::kSaltLen;
    h.ivLen   = AppVer::kIVLen;
    h.tagLen  = AppVer::kTagLen;
    h.salt.resize(h.saltLen);
    h.iv.resize(h.ivLen);

    if (RAND_bytes(reinterpret_cast<unsigned char*>(h.salt.data()), h.salt.size()) != 1 ||
        RAND_bytes(reinterpret_cast<unsigned char*>(h.iv.data()), h.iv.size()) != 1) {
        errorMsg = "RAND_bytes 生成盐或 IV 失败：" + opensslErr();
        return false;
    }

    std::array<unsigned char, 32> key; // AES-256
    if (!deriveKey(password, h.salt, h.iterations, key, errorMsg)) {
        return false;
    }

    QByteArray header = buildHeader(h);
    // Write header
    if (out.write(header) != header.size()) {
        errorMsg = "写入文件头失败";
        return false;
    }

    // Setup OpenSSL AES-256-GCM
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) { errorMsg = "EVP_CIPHER_CTX_new 失败"; return false; }

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        errorMsg = "EVP_EncryptInit_ex 失败：" + opensslErr(); return false;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, h.iv.size(), nullptr) != 1) {
        errorMsg = "设置 GCM IV 长度失败：" + opensslErr(); return false;
    }
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(),
                           reinterpret_cast<const unsigned char*>(h.iv.constData())) != 1) {
        errorMsg = "EVP_EncryptInit_ex 设置密钥/IV 失败：" + opensslErr(); return false;
    }
    // AAD = header
    int outlen = 0;
    if (EVP_EncryptUpdate(ctx.get(), nullptr, &outlen,
                          reinterpret_cast<const unsigned char*>(header.constData()),
                          header.size()) != 1) {
        errorMsg = "设置 AAD 失败：" + opensslErr(); return false;
    }

    // zlib deflate -> gcm encrypt streaming
    ZlibDeflater deflater(Z_BEST_COMPRESSION);
    std::vector<unsigned char> compOut;
    compOut.reserve(1 << 16);
    std::vector<unsigned char> encOut;
    encOut.resize(IO_CHUNK + 32); // output buffer

    qint64 total = in.size(), processed = 0;

    std::vector<unsigned char> inBuf;
    inBuf.resize(IO_CHUNK);

    while (true) {
        qint64 n = in.read(reinterpret_cast<char*>(inBuf.data()), inBuf.size());
        if (n < 0) { errorMsg = "读取输入文件失败"; return false; }
        if (n == 0) break;

        processed += n;
        // compress
        compOut.clear();
        deflater.update(inBuf.data(), static_cast<size_t>(n), compOut);

        // encrypt compressed bytes
        if (!compOut.empty()) {
            int len = 0;
            if (EVP_EncryptUpdate(ctx.get(), encOut.data(), &len, compOut.data(), static_cast<int>(compOut.size())) != 1) {
                errorMsg = "EVP_EncryptUpdate 失败：" + opensslErr(); return false;
            }
            if (len > 0) {
                if (out.write(reinterpret_cast<const char*>(encOut.data()), len) != len) {
                    errorMsg = "写入加密数据失败"; return false;
                }
            }
        }

        if (progress) progress(processed, total);
    }

    // finish deflate
    compOut.clear();
    deflater.finish(compOut);
    if (!compOut.empty()) {
        int len = 0;
        if (EVP_EncryptUpdate(ctx.get(), encOut.data(), &len, compOut.data(), static_cast<int>(compOut.size())) != 1) {
            errorMsg = "EVP_EncryptUpdate finish 失败：" + opensslErr(); return false;
        }
        if (len > 0) {
            if (out.write(reinterpret_cast<const char*>(encOut.data()), len) != len) {
                errorMsg = "写入加密数据失败"; return false;
            }
        }
    }

    // Finalize GCM
    int lenFinal = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), encOut.data(), &lenFinal) != 1) {
        errorMsg = "EVP_EncryptFinal_ex 失败：" + opensslErr(); return false;
    }
    // GCM tag
    std::array<unsigned char, AppVer::kTagLen> tag{};
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, AppVer::kTagLen, tag.data()) != 1) {
        errorMsg = "获取 GCM Tag 失败：" + opensslErr(); return false;
    }
    if (out.write(reinterpret_cast<const char*>(tag.data()), tag.size()) != static_cast<qint64>(tag.size())) {
        errorMsg = "写入 GCM Tag 失败"; return false;
    }

    if (!out.commit()) { errorMsg = "提交输出文件失败"; return false; }
    if (progress) progress(total, total);
    return true;
}

bool decryptFileWithPassword(const QString& inPath, const QString& outPath, const QString& password,
                             const ProgressFn& progress, QString& errorMsg) {
    QFile in(inPath);
    if (!in.exists() || !in.open(QIODevice::ReadOnly)) {
        errorMsg = "无法打开加密输入文件：" + inPath;
        return false;
    }

    // Parse header
    Header h;
    if (!parseHeader(in, h, errorMsg)) return false;
    const qint64 headerSize = 5 + 1 + 1 + 4 + 1 + 1 + 1 + h.saltLen + h.ivLen;
    const qint64 fileSize = in.size();
    if (fileSize < (headerSize + h.tagLen)) {
        errorMsg = "文件长度不正确"; return false;
    }
    const qint64 cipherSize = fileSize - headerSize - h.tagLen;

    // Read tag
    if (!in.seek(headerSize + cipherSize)) { errorMsg = "seek 读取 Tag 失败"; return false; }
    QByteArray tag = in.read(h.tagLen);
    if (tag.size() != h.tagLen) { errorMsg = "读取 Tag 失败"; return false; }

    // Derive key
    std::array<unsigned char, 32> key;
    if (!deriveKey(password, h.salt, h.iterations, key, errorMsg)) return false;

    // Rewind to start of ciphertext
    if (!in.seek(headerSize)) { errorMsg = "seek 到密文开始失败"; return false; }

    // Decrypt to temporary file first
    QTemporaryFile tmp(QDir::temp().filePath("qzae-XXXXXX.tmp"));
    tmp.setAutoRemove(false);
    if (!tmp.open()) { errorMsg = "创建临时文件失败"; return false; }
    const QString tmpPath = tmp.fileName();
    auto cleanupTmp = qScopeGuard([&](){ QFile::remove(tmpPath); });

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) { errorMsg = "EVP_CIPHER_CTX_new 失败"; return false; }
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        errorMsg = "EVP_DecryptInit_ex 失败：" + opensslErr(); return false;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, h.iv.size(), nullptr) != 1) {
        errorMsg = "设置 GCM IV 长度失败：" + opensslErr(); return false;
    }
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(),
                           reinterpret_cast<const unsigned char*>(h.iv.constData())) != 1) {
        errorMsg = "EVP_DecryptInit_ex 设置密钥/IV 失败：" + opensslErr(); return false;
    }
    // AAD = header
    QByteArray header;
    {
        // rebuild header bytes exactly as written
        Header HH = h;
        HH.magic = QByteArray(AppVer::kMagic, 5);
        header = buildHeader(HH);
    }
    int outlen = 0;
    if (EVP_DecryptUpdate(ctx.get(), nullptr, &outlen,
                          reinterpret_cast<const unsigned char*>(header.constData()),
                          header.size()) != 1) {
        errorMsg = "设置 AAD 失败：" + opensslErr(); return false;
    }

    std::vector<unsigned char> inBuf; inBuf.resize(IO_CHUNK);
    std::vector<unsigned char> plainOut; plainOut.resize(IO_CHUNK + 32);

    qint64 processed = 0;
    const qint64 total = cipherSize;
    qint64 left = cipherSize;

    while (left > 0) {
        const qint64 toRead = std::min<qint64>(left, static_cast<qint64>(inBuf.size()));
        qint64 n = in.read(reinterpret_cast<char*>(inBuf.data()), toRead);
        if (n <= 0) { errorMsg = "读取密文失败"; return false; }
        left -= n; processed += n;

        int len = 0;
        if (EVP_DecryptUpdate(ctx.get(), plainOut.data(), &len, inBuf.data(), static_cast<int>(n)) != 1) {
            errorMsg = "EVP_DecryptUpdate 失败：" + opensslErr(); return false;
        }
        if (len > 0) {
            if (tmp.write(reinterpret_cast<const char*>(plainOut.data()), len) != len) {
                errorMsg = "写入临时解密数据失败"; return false;
            }
        }
        if (progress) progress(processed, total);
    }

    // Set expected tag then finalize
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, h.tagLen,
                            const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(tag.constData()))) != 1) {
        errorMsg = "设置 GCM Tag 失败：" + opensslErr(); return false;
    }
    int lenFinal = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), plainOut.data(), &lenFinal) != 1) {
        errorMsg = "GCM 验证失败：密码错误或文件被篡改"; return false;
    }
    if (lenFinal > 0) {
        if (tmp.write(reinterpret_cast<const char*>(plainOut.data()), lenFinal) != lenFinal) {
            errorMsg = "写入临时解密数据失败"; return false;
        }
    }
    tmp.flush();
    tmp.close();

    // Inflate from tmp to outPath
    QSaveFile out(outPath);
    if (!out.open(QIODevice::WriteOnly)) { errorMsg = "打开输出文件失败：" + outPath; return false; }

    QFile comp(tmpPath);
    if (!comp.open(QIODevice::ReadOnly)) { errorMsg = "重新打开临时文件失败"; return false; }

    ZlibInflater inflater;
    std::vector<unsigned char> compBuf; compBuf.resize(IO_CHUNK);
    std::vector<unsigned char> decompOut; decompOut.reserve(1 << 16);

    while (true) {
        qint64 n = comp.read(reinterpret_cast<char*>(compBuf.data()), compBuf.size());
        if (n < 0) { errorMsg = "读取临时压缩数据失败"; return false; }
        if (n == 0) break;
        decompOut.clear();
        inflater.update(compBuf.data(), static_cast<size_t>(n), decompOut);
        if (!decompOut.empty()) {
            if (out.write(reinterpret_cast<const char*>(decompOut.data()), decompOut.size()) != static_cast<qint64>(decompOut.size())) {
                errorMsg = "写入解压输出失败"; return false;
            }
        }
    }
    decompOut.clear();
    inflater.finish(decompOut);
    if (!decompOut.empty()) {
        if (out.write(reinterpret_cast<const char*>(decompOut.data()), decompOut.size()) != static_cast<qint64>(decompOut.size())) {
            errorMsg = "写入解压尾部失败"; return false;
        }
    }
    if (!out.commit()) { errorMsg = "提交输出文件失败"; return false; }

    // Success -> remove tmp
    QFile::remove(tmpPath);
    cleanupTmp.dismiss();
    if (progress) progress(total, total);
    return true;
}
