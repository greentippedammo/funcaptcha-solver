// SHA-256 CUDA Kernel for PoW Mining (binary nonce appended)
// Place this file in: src/main/resources/sha256_kernel.cu

#include <stdint.h>

__constant__ uint32_t K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

__constant__ uint32_t H0_const[8] = {
    0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
    0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
};

__device__ __forceinline__ uint32_t rotr(uint32_t x, int r) {
    return (x >> r) | (x << (32 - r));
}
__device__ __forceinline__ uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
__device__ __forceinline__ uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
__device__ __forceinline__ uint32_t Sigma0(uint32_t x) { return rotr(x,2) ^ rotr(x,13) ^ rotr(x,22); }
__device__ __forceinline__ uint32_t Sigma1(uint32_t x) { return rotr(x,6) ^ rotr(x,11) ^ rotr(x,25); }
__device__ __forceinline__ uint32_t sigma0(uint32_t x) { return rotr(x,7) ^ rotr(x,18) ^ (x >> 3); }
__device__ __forceinline__ uint32_t sigma1(uint32_t x) { return rotr(x,17) ^ rotr(x,19) ^ (x >> 10); }

__device__ __forceinline__ uint32_t load_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | ((uint32_t)p[3]);
}

__device__ void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64];
    #pragma unroll
    for (int t = 0; t < 16; ++t) W[t] = load_be32(block + 4*t);
    for (int t = 16; t < 64; ++t) W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16];

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    #pragma unroll
    for (int t = 0; t < 64; ++t) {
        uint32_t T1 = h + Sigma1(e) + ch(e,f,g) + K[t] + W[t];
        uint32_t T2 = Sigma0(a) + maj(a,b,c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

// compute SHA-256 on a message that is <= 64 bytes or <= 128 bytes after padding.
// We assume input_len <= 56 (so padded fits in one block) OR <= 120 (fits in two blocks).
// This is OK for prefix_len + 8 bytes nonce typical in PoW.
__device__ void sha256_single(const uint8_t* msg, int msg_len, uint8_t out_hash[32]) {
    uint32_t state[8];
    #pragma unroll
    for (int i = 0; i < 8; ++i) state[i] = H0_const[i];

    // compute number of blocks required after padding
    int total_bits = msg_len * 8;
    int first_block_space = 64 - ((msg_len) % 64);
    int blockCount = ((msg_len + 8) / 64) + 1; // safe for msg_len small
    // prepare and process each block
    uint8_t block[64];
    for (int b = 0; b < blockCount; ++b) {
        // fill block with zeros
        #pragma unroll
        for (int i = 0; i < 64; ++i) block[i] = 0;

        int start = b * 64;
        for (int i = 0; i < 64; ++i) {
            int idx = start + i;
            if (idx < msg_len) block[i] = msg[idx];
            else if (idx == msg_len) block[i] = 0x80;
            // else zeros or later length bytes
        }
        // if this is the last block, write length in bits to last 8 bytes (big-endian)
        if (b == blockCount - 1) {
            uint64_t bitLen = ((uint64_t)msg_len) * 8ULL;
            // big-endian into block[56..63]
            block[56] = (uint8_t)((bitLen >> 56) & 0xFF);
            block[57] = (uint8_t)((bitLen >> 48) & 0xFF);
            block[58] = (uint8_t)((bitLen >> 40) & 0xFF);
            block[59] = (uint8_t)((bitLen >> 32) & 0xFF);
            block[60] = (uint8_t)((bitLen >> 24) & 0xFF);
            block[61] = (uint8_t)((bitLen >> 16) & 0xFF);
            block[62] = (uint8_t)((bitLen >> 8) & 0xFF);
            block[63] = (uint8_t)(bitLen & 0xFF);
        }
        sha256_transform(state, block);
    }

    // write out big-endian state
    for (int i = 0; i < 8; ++i) {
        out_hash[4*i + 0] = (uint8_t)((state[i] >> 24) & 0xFF);
        out_hash[4*i + 1] = (uint8_t)((state[i] >> 16) & 0xFF);
        out_hash[4*i + 2] = (uint8_t)((state[i] >> 8) & 0xFF);
        out_hash[4*i + 3] = (uint8_t)( state[i] & 0xFF);
    }
}

__device__ __forceinline__ int hash_below_target(const uint8_t *h, const uint8_t *t) {
    // big-endian compare
    for (int i = 0; i < 32; ++i) {
        if (h[i] < t[i]) return 1;
        if (h[i] > t[i]) return 0;
    }
    return 0;
}

// Main kernel: prefix || 8-byte big-endian nonce
extern "C" __global__ void sha256_mine_binary_nonce(
    const uint8_t* prefix,
    int prefix_len,
    const uint8_t* target,       // 32-byte big-endian target
    uint64_t start_nonce,
    uint64_t* result,
    int* found,
    uint64_t nonce_stride_per_thread // optional: how many nonces each thread checks; pass 1 or more
) {
    uint64_t tid = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
    // each thread may handle multiple nonces in a stride loop
    uint64_t nonce = start_nonce + tid;

    // quick read of found
    if (*found) return;

    // build small buffer prefix + 8 bytes nonce
    // We require prefix_len + 8 <= 120 (so padded message fits within two blocks)
    uint8_t msg[128]; // local
    // copy prefix
    for (int i = 0; i < prefix_len; ++i) msg[i] = prefix[i];

    // now loop through nonces (if stride>1)
    for (uint64_t k = 0; k < (uint64_t)nonce_stride_per_thread; ++k) {
        uint64_t cur = nonce + k * gridDim.x * blockDim.x;
        // append nonce as big-endian 8 bytes
        uint64_t n = cur;
        int base = prefix_len;
        msg[base + 0] = (uint8_t)((n >> 56) & 0xFF);
        msg[base + 1] = (uint8_t)((n >> 48) & 0xFF);
        msg[base + 2] = (uint8_t)((n >> 40) & 0xFF);
        msg[base + 3] = (uint8_t)((n >> 32) & 0xFF);
        msg[base + 4] = (uint8_t)((n >> 24) & 0xFF);
        msg[base + 5] = (uint8_t)((n >> 16) & 0xFF);
        msg[base + 6] = (uint8_t)((n >> 8) & 0xFF);
        msg[base + 7] = (uint8_t)( n        & 0xFF);

        int total_len = prefix_len + 8;

        uint8_t hash[32];
        sha256_single(msg, total_len, hash);

        if (hash_below_target(hash, target)) {
            // winner
            if (atomicCAS(found, 0, 1) == 0) {
                *result = cur;
            }
            return;
        }

        // quick abort check
        if (*found) return;
    }
}
