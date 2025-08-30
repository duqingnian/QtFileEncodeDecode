
#pragma once
#include <zlib.h>
#include <vector>
#include <stdexcept>
#include <cstddef>

class ZlibDeflater {
public:
    explicit ZlibDeflater(int level = Z_DEFAULT_COMPRESSION) {
        z.zalloc = Z_NULL;
        z.zfree = Z_NULL;
        z.opaque = Z_NULL;
        int ret = deflateInit(&z, level);
        if (ret != Z_OK) throw std::runtime_error("deflateInit failed");
    }
    ~ZlibDeflater() { deflateEnd(&z); }

    // Feed input chunk, get zero or more compressed bytes via output buffer.
    // Returns number of bytes produced this call (appended to outVec).
    size_t update(const unsigned char* in, size_t inLen, std::vector<unsigned char>& outVec) {
        z.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(in));
        z.avail_in = static_cast<uInt>(inLen);

        const size_t kChunk = 1 << 16; // 64KB
        size_t produced = 0;
        std::vector<unsigned char> buffer;
        buffer.resize(kChunk);

        while (z.avail_in > 0) {
            z.next_out = buffer.data();
            z.avail_out = static_cast<uInt>(buffer.size());
            int ret = deflate(&z, Z_NO_FLUSH);
            if (ret != Z_OK) throw std::runtime_error("deflate Z_NO_FLUSH failed");
            size_t have = buffer.size() - z.avail_out;
            if (have) {
                outVec.insert(outVec.end(), buffer.data(), buffer.data() + have);
                produced += have;
            }
        }
        return produced;
    }

    // Finish stream, flush remaining compressed data
    size_t finish(std::vector<unsigned char>& outVec) {
        const size_t kChunk = 1 << 16;
        size_t produced = 0;
        std::vector<unsigned char> buffer;
        buffer.resize(kChunk);

        int ret;
        do {
            z.next_out = buffer.data();
            z.avail_out = static_cast<uInt>(buffer.size());
            ret = deflate(&z, Z_FINISH);
            if (ret != Z_OK && ret != Z_STREAM_END) {
                throw std::runtime_error("deflate Z_FINISH failed");
            }
            size_t have = buffer.size() - z.avail_out;
            if (have) {
                outVec.insert(outVec.end(), buffer.data(), buffer.data() + have);
                produced += have;
            }
        } while (ret != Z_STREAM_END);
        return produced;
    }

private:
    z_stream z{};
};

class ZlibInflater {
public:
    ZlibInflater() {
        z.zalloc = Z_NULL;
        z.zfree = Z_NULL;
        z.opaque = Z_NULL;
        int ret = inflateInit(&z);
        if (ret != Z_OK) throw std::runtime_error("inflateInit failed");
    }
    ~ZlibInflater() { inflateEnd(&z); }

    size_t update(const unsigned char* in, size_t inLen, std::vector<unsigned char>& outVec) {
        z.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(in));
        z.avail_in = static_cast<uInt>(inLen);

        const size_t kChunk = 1 << 16;
        size_t produced = 0;
        std::vector<unsigned char> buffer;
        buffer.resize(kChunk);

        while (z.avail_in > 0) {
            z.next_out = buffer.data();
            z.avail_out = static_cast<uInt>(buffer.size());
            int ret = inflate(&z, Z_NO_FLUSH);
            if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
                throw std::runtime_error("inflate failed");
            }
            size_t have = buffer.size() - z.avail_out;
            if (have) {
                outVec.insert(outVec.end(), buffer.data(), buffer.data() + have);
                produced += have;
            }
            if (ret == Z_STREAM_END && z.avail_in == 0) break;
        }
        return produced;
    }

    size_t finish(std::vector<unsigned char>& outVec) {
        // Some streams may require an explicit inflate with empty input to flush.
        return update(reinterpret_cast<const unsigned char*>(""), 0, outVec);
    }

private:
    z_stream z{};
};
