#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable

__constant uint K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

inline uint rotr32(uint x, uint n) {
    return (x >> n) | (x << (32u - n));
}

inline uint ch32(uint x, uint y, uint z) {
    return (x & y) ^ (~x & z);
}

inline uint maj32(uint x, uint y, uint z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint bsig0(uint x) {
    return rotr32(x, 2u) ^ rotr32(x, 13u) ^ rotr32(x, 22u);
}

inline uint bsig1(uint x) {
    return rotr32(x, 6u) ^ rotr32(x, 11u) ^ rotr32(x, 25u);
}

inline uint ssig0(uint x) {
    return rotr32(x, 7u) ^ rotr32(x, 18u) ^ (x >> 3u);
}

inline uint ssig1(uint x) {
    return rotr32(x, 17u) ^ rotr32(x, 19u) ^ (x >> 10u);
}

inline uint read_be32_private(__private const uchar* p) {
    return ((uint)p[0] << 24) | ((uint)p[1] << 16) | ((uint)p[2] << 8) | (uint)p[3];
}

inline void write_be32_private(__private uchar* p, uint v) {
    p[0] = (uchar)((v >> 24) & 0xffu);
    p[1] = (uchar)((v >> 16) & 0xffu);
    p[2] = (uchar)((v >> 8) & 0xffu);
    p[3] = (uchar)(v & 0xffu);
}

inline void sha256_bytes_private(__private const uchar* data, uint len, __private uchar out[32]) {
    uint H[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };

    __private uchar msg[128];
    for (uint i = 0u; i < 128u; ++i) {
        msg[i] = (uchar)0;
    }

    for (uint i = 0u; i < len; ++i) {
        msg[i] = data[i];
    }
    msg[len] = (uchar)0x80;

    ulong bit_len = ((ulong)len) * 8UL;
    uint total = (len + 9u <= 64u) ? 64u : 128u;
    for (uint i = 0u; i < 8u; ++i) {
        msg[total - 1u - i] = (uchar)((bit_len >> (8u * i)) & 0xffUL);
    }

    for (uint chunk = 0u; chunk < total; chunk += 64u) {
        uint w[64];
        for (uint i = 0u; i < 16u; ++i) {
            w[i] = read_be32_private(&msg[chunk + (i * 4u)]);
        }
        for (uint i = 16u; i < 64u; ++i) {
            w[i] = ssig1(w[i - 2u]) + w[i - 7u] + ssig0(w[i - 15u]) + w[i - 16u];
        }

        uint a = H[0];
        uint b = H[1];
        uint c = H[2];
        uint d = H[3];
        uint e = H[4];
        uint f = H[5];
        uint g = H[6];
        uint h = H[7];

        for (uint i = 0u; i < 64u; ++i) {
            uint t1 = h + bsig1(e) + ch32(e, f, g) + K[i] + w[i];
            uint t2 = bsig0(a) + maj32(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }

    for (uint i = 0u; i < 8u; ++i) {
        write_be32_private(&out[i * 4u], H[i]);
    }
}

inline int hash_meets_target_be(__private const uchar hash_raw[32], __global const uchar* target_be) {
    for (uint i = 0u; i < 32u; ++i) {
        uchar hb = hash_raw[31u - i];
        uchar tb = target_be[i];
        if (hb < tb) return 1;
        if (hb > tb) return 0;
    }
    return 1;
}

__kernel void btc_sha256d_scan(
    __global const uchar* header_prefix76,
    const uint nonce_count,
    const uint start_nonce,
    __global const uchar* target32_be,
    const uint max_results,
    __global uint* out_nonces,
    __global uchar* out_hashes32_be,
    __global uint* out_count
) {
    uint gid = (uint)get_global_id(0);
    if (gid >= nonce_count) {
        return;
    }

    uint nonce = start_nonce + gid;

    __private uchar header80[80];
    for (uint i = 0u; i < 76u; ++i) {
        header80[i] = header_prefix76[i];
    }
    header80[76] = (uchar)(nonce & 0xffu);
    header80[77] = (uchar)((nonce >> 8) & 0xffu);
    header80[78] = (uchar)((nonce >> 16) & 0xffu);
    header80[79] = (uchar)((nonce >> 24) & 0xffu);

    __private uchar hash1[32];
    __private uchar hash2[32];

    sha256_bytes_private(header80, 80u, hash1);
    sha256_bytes_private(hash1, 32u, hash2);

    if (!hash_meets_target_be(hash2, target32_be)) {
        return;
    }

    uint slot = atomic_inc((volatile __global uint*)out_count);
    if (slot >= max_results) {
        return;
    }

    out_nonces[slot] = nonce;
    for (uint i = 0u; i < 32u; ++i) {
        out_hashes32_be[(slot * 32u) + i] = hash2[31u - i];
    }
}