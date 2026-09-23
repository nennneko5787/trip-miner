import Foundation

/// Web版 trip-miner.js の CommonUtils / CryptModeStrategy に対応する
/// トリップ仕様・キー空間の定義。桁数ごとの alphabet と seed 進行を集約する。
enum TripSpec {
    /// 10桁(crypt)用 alphabet。JS: BASE64_ALPHABET_CRYPT
    static let alphabet10 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    /// 12桁(sha)用 alphabet。JS: BASE64_ALPHABET_SHA
    static let alphabet12 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./"

    static let chars10: [Character] = Array(alphabet10)
    static let chars12: [Character] = Array(alphabet12)

    /// 10桁・後方一致で末尾に許される文字集合 (DES crypt の制約)
    static let validSuffixLast10: Set<Character> = Set(".26AEIMQUYcgkosw")

    /// 64bit加算。JS: CommonUtils.add64 — (lo, hi) + add
    static func add64(lo: UInt32, hi: UInt32, add: UInt32) -> (lo: UInt32, hi: UInt32) {
        let newLo = lo &+ add
        let carry: UInt32 = newLo < lo ? 1 : 0
        return (newLo, hi &+ carry)
    }

    // MARK: - 10桁(crypt) seed

    /// 下位・上位各バイトの 0x00 を 0x01 に置換。JS: _sanitizeZeroBytes
    static func sanitizeZeroBytes(lo: UInt32, hi: UInt32) -> (lo: UInt32, hi: UInt32) {
        var lo = lo, hi = hi
        for i in 0..<4 {
            if ((lo >> (i * 8)) & 0xFF) == 0 { lo |= (1 << (i * 8)) }
            if ((hi >> (i * 8)) & 0xFF) == 0 { hi |= (1 << (i * 8)) }
        }
        return (lo, hi)
    }

    static func randomSeed10() -> (lo: UInt32, hi: UInt32) {
        sanitizeZeroBytes(lo: UInt32.random(in: .min ... .max), hi: UInt32.random(in: .min ... .max))
    }

    static func advanceSeed10(lo: UInt32, hi: UInt32, step: UInt32) -> (lo: UInt32, hi: UInt32) {
        let n = add64(lo: lo, hi: hi, add: step)
        return sanitizeZeroBytes(lo: n.lo, hi: n.hi)
    }

    static func hashesPerIteration10(workgroups: Int, workgroupSize: Int) -> Int {
        workgroups * workgroupSize * 32
    }

    /// 1スレッドが32lane×step7で消費するキー数。JS: getStep
    static func step10(workgroups: Int, workgroupSize: Int) -> UInt32 {
        UInt32(workgroups * workgroupSize * 32 * 7)
    }

    // MARK: - 12桁(sha) seed

    static func randomMessage12() -> String {
        String((0..<12).map { _ in chars12[Int.random(in: 0..<64)] })
    }

    /// base64カウンタ加算。JS: incrementBase64Message
    static func incrementMessage12(_ base: String, by index: UInt32) -> String {
        var chars = Array(base)
        var carry = UInt64(index)
        var i = 11
        while i >= 0 && carry > 0 {
            guard let pos = chars12.firstIndex(of: chars[i]) else { break }
            let sum = UInt64(pos) + carry
            chars[i] = chars12[Int(sum % 64)]
            carry = sum / 64
            i -= 1
        }
        return String(chars)
    }

    static func hashesPerIteration12(workgroups: Int, workgroupSize: Int) -> Int {
        workgroups * workgroupSize * 32
    }

    static func step12(workgroups: Int, workgroupSize: Int) -> UInt32 {
        UInt32(workgroups * workgroupSize * 32)
    }

    /// "#" 始まりのキーを正規化。JS: normalizeShaMessage
    static func normalizeShaMessage(_ msg: String) -> String {
        msg.hasPrefix("#") ? String(msg.dropFirst()) : msg
    }

    /// keyDecode: 64bitキー + salt2文字 → 表示用キー文字列
    static func keyDecode(key: UInt64, salt1: Int, salt2: Int) -> String {
        let hex = String(format: "%016llx", key)
        let salt = [salt1, salt2].map { t -> Character in
            var v = t + 46 // "."
            if v > 57 { v += 7 } // "9"
            if v > 90 { v += 6 } // "Z"
            return Character(UnicodeScalar(v)!)
        }
        return hex + String(salt)
    }
}
