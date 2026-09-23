#include <metal_stdlib>
using namespace metal;

// Web版 sha-regex.wgsl の MSL 移植。
// 第1パス出力のダイジェストを72プレーンにbitslice化し、生成matcherで判定する。

struct ShaRegexParams {
  uint total_lanes;
  uint batch_index;
  uint batch_count;
  uint _pad2;
};

#regex_matcher_code

kernel void main(uint gid [[thread_position_in_grid]],
                 device const uint *digest_input [[buffer(0)]],
                 constant ShaRegexParams &params [[buffer(1)]],
                 device uint *output_mask [[buffer(2)]]) {
  uint chunks_per_batch = (params.total_lanes + 31u) / 32u;
  uint chunk = gid % chunks_per_batch;
  uint batch = gid / chunks_per_batch;
  uint lane_base = chunk * 32u;

  if (batch >= params.batch_count || lane_base >= params.total_lanes) {
    return;
  }

  uint planes[72];
  for (uint i = 0; i < 72; i++) {
    planes[i] = 0u;
  }

  for (uint lane = 0; lane < 32; lane++) {
    uint idx = lane_base + lane;
    if (idx >= params.total_lanes) {
      break;
    }
    uint base = ((batch * params.total_lanes) + idx) * 3u;
    uint d0 = digest_input[base];
    uint d1 = digest_input[base + 1u];
    uint d2 = digest_input[base + 2u];
    uint mask = 1u << lane;
    for (uint b = 0; b < 32; b++) {
      if (((d0 >> (31u - b)) & 1u) != 0u) {
        planes[b] |= mask;
      }
    }
    for (uint b = 0; b < 32; b++) {
      if (((d1 >> (31u - b)) & 1u) != 0u) {
        planes[b + 32u] |= mask;
      }
    }
    for (uint b = 0; b < 8; b++) {
      if (((d2 >> (31u - b)) & 1u) != 0u) {
        planes[b + 64u] |= mask;
      }
    }
  }

  output_mask[batch * chunks_per_batch + chunk] = regex_match(planes);
}
