// @vasic_mode candidate_merge
// @vasic_count_arg 4
// @vasic_merge_buffer 2:4
// @vasic_merge_buffer 3:32
// @vasic_partition scalar_u32:5

#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable

#ifndef VASIC_CPU_LANE
#define VASIC_CPU_LANE 0
#endif

#ifndef VASIC_ENABLE_DUAL_LANE
#define VASIC_ENABLE_DUAL_LANE 1
#endif

#ifndef VASIC_USE_LOCAL_STAGING
#define VASIC_USE_LOCAL_STAGING 1
#endif

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

inline uint rotr32(uint x, uint n) { return rotate(x, 32u - n); }
inline uint ch32(uint x, uint y, uint z) { return (x & y) ^ (~x & z); }
inline uint maj32(uint x, uint y, uint z) { return (x & y) ^ (x & z) ^ (y & z); }
inline uint bsig0(uint x) { return rotr32(x, 2u) ^ rotr32(x, 13u) ^ rotr32(x, 22u); }
inline uint bsig1(uint x) { return rotr32(x, 6u) ^ rotr32(x, 11u) ^ rotr32(x, 25u); }
inline uint ssig0(uint x) { return rotr32(x, 7u) ^ rotr32(x, 18u) ^ (x >> 3u); }
inline uint ssig1(uint x) { return rotr32(x, 17u) ^ rotr32(x, 19u) ^ (x >> 10u); }

inline uint read_be32_global(__global const uchar* p) {
    return ((uint)p[0] << 24) |
           ((uint)p[1] << 16) |
           ((uint)p[2] <<  8) |
           ((uint)p[3]);
}

inline void write_le32_global(__global uchar* p, uint v) {
    p[0] = (uchar)(v & 0xffu);
    p[1] = (uchar)((v >> 8) & 0xffu);
    p[2] = (uchar)((v >> 16) & 0xffu);
    p[3] = (uchar)((v >> 24) & 0xffu);
}

inline uint bswap32(uint x) {
    return ((x & 0x000000ffu) << 24) |
           ((x & 0x0000ff00u) <<  8) |
           ((x & 0x00ff0000u) >>  8) |
           ((x & 0xff000000u) >> 24);
}

inline void sha256_init(__private uint s[8]) {
    s[0] = 0x6a09e667u;
    s[1] = 0xbb67ae85u;
    s[2] = 0x3c6ef372u;
    s[3] = 0xa54ff53au;
    s[4] = 0x510e527fu;
    s[5] = 0x9b05688cu;
    s[6] = 0x1f83d9abu;
    s[7] = 0x5be0cd19u;
}

inline void sha256_compress_16w(__private uint state[8], __private uint w[16]) {
    uint a = state[0];
    uint b = state[1];
    uint c = state[2];
    uint d = state[3];
    uint e = state[4];
    uint f = state[5];
    uint g = state[6];
    uint h = state[7];

    #pragma unroll
    for (uint i = 0u; i < 16u; ++i) {
        uint t1 = h + bsig1(e) + ch32(e, f, g) + K[i] + w[i];
        uint t2 = bsig0(a) + maj32(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    #pragma unroll
    for (uint i = 16u; i < 64u; ++i) {
        uint wi = w[i & 15u]
                + ssig0(w[(i + 1u) & 15u])
                + w[(i + 9u) & 15u]
                + ssig1(w[(i + 14u) & 15u]);
        w[i & 15u] = wi;

        uint t1 = h + bsig1(e) + ch32(e, f, g) + K[i] + wi;
        uint t2 = bsig0(a) + maj32(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

inline int btc_hash_meets_target_from_state(
    __private const uint s2[8],
#if VASIC_USE_LOCAL_STAGING
    __local const uint* target_be_words
#else
    __private const uint* target_be_words
#endif
) {
    uint hv;

    hv = bswap32(s2[7]); if (hv < target_be_words[0]) return 1; if (hv > target_be_words[0]) return 0;
    hv = bswap32(s2[6]); if (hv < target_be_words[1]) return 1; if (hv > target_be_words[1]) return 0;
    hv = bswap32(s2[5]); if (hv < target_be_words[2]) return 1; if (hv > target_be_words[2]) return 0;
    hv = bswap32(s2[4]); if (hv < target_be_words[3]) return 1; if (hv > target_be_words[3]) return 0;
    hv = bswap32(s2[3]); if (hv < target_be_words[4]) return 1; if (hv > target_be_words[4]) return 0;
    hv = bswap32(s2[2]); if (hv < target_be_words[5]) return 1; if (hv > target_be_words[5]) return 0;
    hv = bswap32(s2[1]); if (hv < target_be_words[6]) return 1; if (hv > target_be_words[6]) return 0;
    hv = bswap32(s2[0]); if (hv < target_be_words[7]) return 1; if (hv > target_be_words[7]) return 0;

    return 1;
}

inline uint vasic_partitioned_nonce(uint gid, uint start_nonce) {
#if VASIC_ENABLE_DUAL_LANE
    return start_nonce + gid;
#else
    return start_nonce + gid;
#endif
}

__kernel void btc_sha256d_scan(
    __global const uchar* header_prefix76,
    __global const uchar* target32_be,
    __global uint* out_nonces,
    __global uchar* out_hashes32_be,
    __global uint* out_count,
    const uint start_nonce,
    const uint max_results
) {
    const uint gid = (uint)get_global_id(0);
    const uint lid = (uint)get_local_id(0);

#if VASIC_USE_LOCAL_STAGING
    __local uint l_midstate[8];
    __local uint l_tail0;
    __local uint l_tail1;
    __local uint l_tail2;
    __local uint l_target[8];
#else
    uint l_midstate[8];
    uint l_tail0;
    uint l_tail1;
    uint l_tail2;
    uint l_target[8];
#endif

#if VASIC_USE_LOCAL_STAGING
    if (lid == 0u) {
#endif
        uint s[8];
        uint w[16];

        sha256_init(s);

        #pragma unroll
        for (uint i = 0u; i < 16u; ++i) {
            w[i] = read_be32_global(header_prefix76 + (i * 4u));
        }
        sha256_compress_16w(s, w);

        #pragma unroll
        for (uint i = 0u; i < 8u; ++i) {
            l_midstate[i] = s[i];
        }

        l_tail0 = read_be32_global(header_prefix76 + 64u);
        l_tail1 = read_be32_global(header_prefix76 + 68u);
        l_tail2 = read_be32_global(header_prefix76 + 72u);

        #pragma unroll
        for (uint i = 0u; i < 8u; ++i) {
            l_target[i] = read_be32_global(target32_be + (i * 4u));
        }
#if VASIC_USE_LOCAL_STAGING
    }

    barrier(CLK_LOCAL_MEM_FENCE);
#endif

    const uint nonce = vasic_partitioned_nonce(gid, start_nonce);

    uint s1[8];
    uint w1[16];

    #pragma unroll
    for (uint i = 0u; i < 8u; ++i) {
        s1[i] = l_midstate[i];
    }

    w1[0]  = l_tail0;
    w1[1]  = l_tail1;
    w1[2]  = l_tail2;
    w1[3]  = bswap32(nonce);
    w1[4]  = 0x80000000u;
    w1[5]  = 0u;
    w1[6]  = 0u;
    w1[7]  = 0u;
    w1[8]  = 0u;
    w1[9]  = 0u;
    w1[10] = 0u;
    w1[11] = 0u;
    w1[12] = 0u;
    w1[13] = 0u;
    w1[14] = 0u;
    w1[15] = 0x00000280u;

    sha256_compress_16w(s1, w1);

    uint s2[8];
    uint w2[16];

    sha256_init(s2);

    w2[0]  = s1[0];
    w2[1]  = s1[1];
    w2[2]  = s1[2];
    w2[3]  = s1[3];
    w2[4]  = s1[4];
    w2[5]  = s1[5];
    w2[6]  = s1[6];
    w2[7]  = s1[7];
    w2[8]  = 0x80000000u;
    w2[9]  = 0u;
    w2[10] = 0u;
    w2[11] = 0u;
    w2[12] = 0u;
    w2[13] = 0u;
    w2[14] = 0u;
    w2[15] = 0x00000100u;

    sha256_compress_16w(s2, w2);

    if (!btc_hash_meets_target_from_state(s2, l_target)) {
        return;
    }

    uint slot = atomic_inc((volatile __global uint*)out_count);
    if (slot >= max_results) {
        return;
    }

    out_nonces[slot] = nonce;

    __global uchar* dst = out_hashes32_be + (slot * 32u);
    write_le32_global(dst +  0u, s2[7]);
    write_le32_global(dst +  4u, s2[6]);
    write_le32_global(dst +  8u, s2[5]);
    write_le32_global(dst + 12u, s2[4]);
    write_le32_global(dst + 16u, s2[3]);
    write_le32_global(dst + 20u, s2[2]);
    write_le32_global(dst + 24u, s2[1]);
    write_le32_global(dst + 28u, s2[0]);
}