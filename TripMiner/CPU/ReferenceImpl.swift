import Foundation

/// CPUリファレンス実装。Web版 CommonUtils.sha1CPU / cryptCPU に対応。
/// GPU結果の検証・Metal不可端末のフォールバック用。
enum ReferenceImpl {
    // MARK: - SHA-1 (pure Swift)

    private static func rotl(_ x: UInt32, _ n: UInt32) -> UInt32 {
        (x << n) | (x >> (32 - n))
    }

    static func sha1(_ message: [UInt8]) -> [UInt8] {
        var msg = message
        let bitLen = UInt64(message.count) * 8
        msg.append(0x80)
        while msg.count % 64 != 56 { msg.append(0) }
        for i in (0..<8).reversed() { msg.append(UInt8((bitLen >> (i * 8)) & 0xFF)) }
        var h: [UInt32] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
        for chunk in stride(from: 0, to: msg.count, by: 64) {
            var w = [UInt32](repeating: 0, count: 80)
            for t in 0..<16 {
                w[t] = (UInt32(msg[chunk + t * 4]) << 24) | (UInt32(msg[chunk + t * 4 + 1]) << 16)
                    | (UInt32(msg[chunk + t * 4 + 2]) << 8) | UInt32(msg[chunk + t * 4 + 3])
            }
            for t in 16..<80 { w[t] = rotl(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16], 1) }
            var (a, b, c, d, e) = (h[0], h[1], h[2], h[3], h[4])
            for t in 0..<80 {
                let f: UInt32
                let k: UInt32
                switch t {
                case 0..<20: f = (b & c) | (~b & d); k = 0x5A827999
                case 20..<40: f = b ^ c ^ d; k = 0x6ED9EBA1
                case 40..<60: f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC
                default: f = b ^ c ^ d; k = 0xCA62C1D6
                }
                let t2 = rotl(a, 5) &+ f &+ e &+ k &+ w[t]
                e = d; d = c; c = rotl(b, 30); b = a; a = t2
            }
            h[0] = h[0] &+ a; h[1] = h[1] &+ b; h[2] = h[2] &+ c; h[3] = h[3] &+ d; h[4] = h[4] &+ e
        }
        var out: [UInt8] = []
        for v in h { for i in (0..<4).reversed() { out.append(UInt8((v >> (i * 8)) & 0xFF)) } }
        return out
    }

    /// 12桁トリップ。JS: sha1CPU — base64('+→.')先頭12文字
    static func sha12(_ message: String) -> String {
        let digest = sha1(Array(message.utf8))
        let b64 = Data(digest).base64EncodedString().replacingOccurrences(of: "+", with: ".")
        return String(b64.prefix(12))
    }

    // MARK: - DES crypt (10桁)

    // 標準DESテーブル (0-indexed, MSB-first)
    private static let eTable: [Int] = [
        31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9, 10, 11, 12,
        11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24,
        23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0,
    ]
    private static let pTable: [Int] = [
        15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9,
        1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24,
    ]
    private static let pc1: [Int] = [
        56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17,
        9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35,
        62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
        13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3,
    ]
    private static let pc2: [Int] = [
        13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3,
        25, 7, 15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46, 54, 29, 39,
        50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31,
    ]
    private static let rotations = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    private static let sBoxes: [[Int]] = [
        [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
        [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
        [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
        [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
        [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
        [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
        [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
        [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
    ]

    @inline(__always) private static func bit(_ v: UInt32, _ i: Int) -> UInt32 { (v >> (31 - i)) & 1 }

    private static func feistel(_ r: UInt32, _ subkey: [UInt32], _ emod: [Int]) -> UInt32 {
        var x = [UInt32](repeating: 0, count: 48)
        for k in 0..<48 { x[k] = bit(r, emod[k]) ^ subkey[k] }
        var s: UInt32 = 0
        for g in 0..<8 {
            let b = (0..<6).map { x[g * 6 + $0] }
            let row = (b[0] << 1) | b[5]
            let col = (b[1] << 3) | (b[2] << 2) | (b[3] << 1) | b[4]
            s |= UInt32(sBoxes[g][row * 16 + col]) << (28 - g * 4)
        }
        var p: UInt32 = 0
        for i in 0..<32 { p |= ((s >> (31 - pTable[i])) & 1) << (31 - i) }
        return p
    }

    /// 10桁トリップ。key は64bit生キー、salt は起動時乱数。
    /// ビット抽出は JS cryptCPU と同一 (FP適用前の状態から60bitを取り出す)。
    static func crypt10(key: UInt64, salt1: Int, salt2: Int) -> String {
        // 鍵ビット (1-indexed相当 → 0-indexed MSB-first)
        var kb = [UInt32](repeating: 0, count: 64)
        for i in 0..<64 { kb[i] = UInt32((key >> (63 - i)) & 1) }
        // PC-1
        var cd = pc1.map { kb[$0] }
        // サブキー16個
        var subkeys: [[UInt32]] = []
        var c = Array(cd[0..<28]), d = Array(cd[28..<56])
        for r in 0..<16 {
            c = Array(c[rotations[r]...] + c[..<rotations[r]])
            d = Array(d[rotations[r]...] + d[..<rotations[r]])
            let full = c + d
            subkeys.append(pc2.map { full[$0] })
        }
        // salt適用E-box
        let salt = salt1 | (salt2 << 6)
        var emod = eTable
        for i in 0..<12 where (salt & (1 << i)) != 0 { emod.swapAt(i, i + 24) }
        // 平文0から25反復 (IPは0に恒等なので省略 — WGSLと同一)
        var l: UInt32 = 0, r: UInt32 = 0
        for _ in 0..<25 {
            for k in subkeys {
                let nl = r
                r = l ^ feistel(r, k, emod)
                l = nl
            }
        }
        // JS と同一の抽出
        let idx: [UInt32] = [
            (l >> 20) & 0x3F, (l >> 14) & 0x3F, (l >> 8) & 0x3F, (l >> 2) & 0x3F,
            ((l & 0x3) << 4) | (r >> 28), (r >> 22) & 0x3F, (r >> 16) & 0x3F,
            (r >> 10) & 0x3F, (r >> 4) & 0x3F, (r << 2) & 0x3F,
        ]
        let alpha = Array(TripSpec.alphabet10)
        return String(idx.map { alpha[Int($0)] })
    }
}
