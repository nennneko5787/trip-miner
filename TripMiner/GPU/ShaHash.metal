#include <metal_stdlib>
using namespace metal;

// Web版 sha-hash.wgsl の MSL 移植。1スレッド=1メッセージのSHA-1。
// 正規表現マッチャは含まない(第2パスで処理)。

struct ShaMessage {
  uint m0;
  uint m1;
  uint m2;
  uint _pad;
};

struct ShaCharMap {
  uint digit_to_ascii[64];
  uint ascii_to_digit[256];
};

struct ShaParams {
  uint total_lanes;
  uint batch_index;
  uint batch_count;
  uint _pad2;
};

inline uint table_digit_to_ascii(constant ShaCharMap &cm, uint d) {
  return cm.digit_to_ascii[d];
}

inline uint table_ascii_to_digit(constant ShaCharMap &cm, uint a) {
  return cm.ascii_to_digit[64 + a];
}

inline uint3 add_message_base64(uint3 base, uint index, constant ShaCharMap &cmap) {
  uint3 result = base;
  uint carry = index;
  for (uint i = 0; i < 12 && carry > 0; i++) {
    uint pos = 2 - (i / 4);
    uint byte_offset = i & 3u;
    uint shift = byte_offset * 8u;
    uint ascii_val = 0;
    if (pos == 0) ascii_val = (result.x >> shift) & 0xFFu;
    else if (pos == 1) ascii_val = (result.y >> shift) & 0xFFu;
    else ascii_val = (result.z >> shift) & 0xFFu;
    uint digit = table_ascii_to_digit(cmap, ascii_val);
    uint sum = digit + carry;
    carry = sum >> 6u;
    sum = sum & 63u;
    uint out_ascii = table_digit_to_ascii(cmap, sum);
    if (pos == 0) result.x = (result.x & ~(0xFFu << shift)) | (out_ascii << shift);
    else if (pos == 1) result.y = (result.y & ~(0xFFu << shift)) | (out_ascii << shift);
    else result.z = (result.z & ~(0xFFu << shift)) | (out_ascii << shift);
  }
  return result;
}

inline uint rotl(uint x, uint n) {
  return (x << n) | (x >> (32u - n));
}

inline uint3 sha1_msg(uint3 message) {
  uint block0 = message.x;
  uint block1 = message.y;
  uint block2 = message.z;
  uint block3 = 0x80000000u;
  uint block15 = 96u;

  uint W[80];
  W[0] = block0; W[1] = block1; W[2] = block2; W[3] = block3;
  for (uint t = 4; t < 15; t++) { W[t] = 0u; }
  W[15] = block15;
  for (uint t = 16; t < 80; t++) {
    W[t] = rotl(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1u);
  }

  uint h0 = 0x67452301u;
  uint h1 = 0xEFCDAB89u;
  uint h2 = 0x98BADCFEu;
  uint h3 = 0x10325476u;
  uint h4 = 0xC3D2E1F0u;

  uint a = h0, b = h1, c = h2, d = h3, e = h4;
  for (uint t = 0; t < 20; t++) {
    uint T = rotl(a, 5u) + ((b & c) | ((~b) & d)) + e + 0x5A827999u + W[t];
    e = d; d = c; c = rotl(b, 30u); b = a; a = T;
  }
  for (uint t = 20; t < 40; t++) {
    uint T = rotl(a, 5u) + (b ^ c ^ d) + e + 0x6ED9EBA1u + W[t];
    e = d; d = c; c = rotl(b, 30u); b = a; a = T;
  }
  for (uint t = 40; t < 60; t++) {
    uint T = rotl(a, 5u) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDCu + W[t];
    e = d; d = c; c = rotl(b, 30u); b = a; a = T;
  }
  for (uint t = 60; t < 80; t++) {
    uint T = rotl(a, 5u) + (b ^ c ^ d) + e + 0xCA62C1D6u + W[t];
    e = d; d = c; c = rotl(b, 30u); b = a; a = T;
  }

  h0 = h0 + a; h1 = h1 + b; h2 = h2 + c;
  return uint3(h0, h1, h2);
}

kernel void shaHashMain(uint gid [[thread_position_in_grid]],
                 constant ShaMessage &base_message [[buffer(0)]],
                 constant ShaCharMap &char_map [[buffer(1)]],
                 constant ShaParams &params [[buffer(2)]],
                 device uint *digest_output [[buffer(3)]]) {
  if (gid >= params.total_lanes) {
    return;
  }
  uint3 message = uint3(base_message.m0, base_message.m1, base_message.m2);
  message = add_message_base64(message, gid, char_map);
  uint3 digest = sha1_msg(message);
  uint base = (params.batch_index * params.total_lanes + gid) * 3u;
  digest_output[base] = digest.x;
  digest_output[base + 1u] = digest.y;
  digest_output[base + 2u] = digest.z;
}
