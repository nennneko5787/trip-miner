import Foundation
import Metal

/// 10桁(crypt/DES)モード。Web版 CryptModeStrategy に対応。
/// Metal が使えない端末では CPU リファレンスにフォールバックする。
final class CryptMiner {
    var salt1 = Int.random(in: 0..<64)
    var salt2 = Int.random(in: 0..<64)

    private var pipeline: MTLComputePipelineState?
    private var tuning: MetalEngine.TuneResult = .init(threadgroups: 32, threadWidth: 32)
    private var inBuf, outBuf, pc2Buf, eboxBuf: MTLBuffer?
    private(set) var laneCount = 0

    var saltValue: Int { salt1 | (salt2 << 6) }

    /// E-box salt適用。JS: getModifiedEBox
    static func modifiedEBox(salt: Int) -> [UInt32] {
        var e: [UInt32] = [
            63, 32, 33, 34, 35, 36,
            35, 36, 37, 38, 39, 40,
            39, 40, 41, 42, 43, 44,
            43, 44, 45, 46, 47, 48,
            47, 48, 49, 50, 51, 52,
            51, 52, 53, 54, 55, 56,
            55, 56, 57, 58, 59, 60,
            59, 60, 61, 62, 63, 32,
        ]
        for i in 0..<12 where (salt & (1 << i)) != 0 {
            e.swapAt(i, i + 24)
        }
        return e
    }

    /// PC2テーブル。JS: createPC2Table
    static func pc2Table() -> [UInt32] {
        let base = [13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31]
        let shifts = [1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 0]
        var t = [UInt32](repeating: 0, count: 16 * 48)
        for r in 0..<16 {
            for i in 0..<48 {
                let b = base[i] >= 28 ? 28 : 0
                let x = (base[i] - b) + shifts[r]
                t[r * 48 + i] = UInt32(b + (x >= 28 ? x - 28 : x))
            }
        }
        return t
    }

    /// matcher を埋め込んだパイプラインを構築する
    func prepare(matcher: String, threadWidth: Int) throws {
        let engine = MetalEngine.shared
        guard engine.isAvailable else { pipeline = nil; return }
        let ebox = Self.modifiedEBox(salt: saltValue)
        guard let url = Bundle.main.url(forResource: "Crypt", withExtension: "metal") else {
            throw MetalEngine.MetalError.missingFunction("Crypt.metal")
        }
        let src = try String(contentsOf: url, encoding: .utf8)
        // E-box salt適用は ebox バッファで渡す(MSL版の方式)。テキスト置換は不要
        let lib = try engine.makeLibrary(baseSource: src, matcher: matcher, threadWidth: threadWidth, key: "crypt")
        pipeline = try engine.makePipeline(library: lib)
    }

    struct CryptParamsWire { var baseLo: UInt32; var baseHi: UInt32; var count: UInt32; var pad: UInt32 }

    func allocate(threadgroups: Int, threadWidth: Int) throws {
        let engine = MetalEngine.shared
        guard engine.isAvailable, let device = engine.device else { return }
        laneCount = threadgroups * threadWidth
        inBuf = device.makeBuffer(length: MemoryLayout<CryptParamsWire>.stride, options: .storageModeShared)
        outBuf = device.makeBuffer(length: laneCount * 4, options: .storageModeShared)
        let pc2 = Self.pc2Table()
        pc2Buf = device.makeBuffer(bytes: pc2, length: pc2.count * 4, options: .storageModeShared)
        let ebox = Self.modifiedEBox(salt: saltValue)
        eboxBuf = device.makeBuffer(bytes: ebox, length: ebox.count * 4, options: .storageModeShared)
        tuning = .init(threadgroups: threadgroups, threadWidth: threadWidth)
    }

    /// 1イテレーション実行 → (経過ms, マスク配列)
    func runBatch(seedLo: UInt32, seedHi: UInt32) throws -> (elapsedMs: Double, masks: [UInt32]) {
        let engine = MetalEngine.shared
        guard let pipeline, let inBuf, let outBuf, let pc2Buf, let eboxBuf else {
            throw MetalEngine.MetalError.encodeFailed
        }
        var params = CryptParamsWire(baseLo: seedLo, baseHi: seedHi, count: UInt32(laneCount), pad: 0)
        memcpy(inBuf.contents(), &params, MemoryLayout<CryptParamsWire>.stride)
        memset(outBuf.contents(), 0, laneCount * 4)
        let ms = try engine.dispatch(
            pipeline: pipeline,
            bindings: [inBuf, outBuf, pc2Buf, eboxBuf],
            threadgroups: tuning.threadgroups, threadsPerGroup: tuning.threadWidth)
        let ptr = outBuf.contents().bindMemory(to: UInt32.self, capacity: laneCount)
        return (ms, Array(UnsafeBufferPointer(start: ptr, count: laneCount)))
    }

    /// マスク → (キー表示, トリップ)。JS execute のデコード部に対応
    func decode(masks: [UInt32], seedLo: UInt32, seedHi: UInt32) -> [(key: String, trip: String)] {
        var out: [(String, String)] = []
        for (i, m) in masks.enumerated() {
            var mask = m
            while mask != 0 {
                // JS: lane = 31 - clz32(mask & -mask); mask &= mask - 1
                let lsb = mask & (~mask &+ 1)
                let lane = lsb.trailingZeroBitCount
                let offset = UInt32((i * 32 + lane) * 7)
                let key = TripSpec.add64(lo: seedLo, hi: seedHi, add: offset)
                let k64 = (UInt64(key.hi) << 32) | UInt64(key.lo)
                let hex = String(format: "%016llx", k64)
                let bytes = stride(from: 0, to: 14, by: 2).map {
                    String(hex[hex.index(hex.startIndex, offsetBy: $0)..<hex.index(hex.startIndex, offsetBy: $0 + 2)])
                }
                if !bytes.contains("00") {
                    let trip = ReferenceImpl.crypt10(key: k64, salt1: salt1, salt2: salt2)
                    out.append((TripSpec.keyDecode(key: k64, salt1: salt1, salt2: salt2), trip))
                }
                mask &= mask &- 1
            }
        }
        return out
    }

    /// CPUフォールバックで1バッチ探索する (Metal不可時・検証用)
    func searchCPU(seedLo: UInt32, seedHi: UInt32, count: Int, match: (String) -> Bool) -> [(key: String, trip: String)] {
        var out: [(String, String)] = []
        var lo = seedLo, hi = seedHi
        for _ in 0..<count {
            let key = (UInt64(hi) << 32) | UInt64(lo)
            let hex = String(format: "%016llx", key)
            // 00 バイト除外 (JS execute と同一)
            let bytes = stride(from: 0, to: 14, by: 2).map { String(hex[hex.index(hex.startIndex, offsetBy: $0)..<hex.index(hex.startIndex, offsetBy: $0 + 2)]) }
            if !bytes.contains("00") {
                let trip = ReferenceImpl.crypt10(key: key, salt1: salt1, salt2: salt2)
                if match(trip) {
                    out.append((TripSpec.keyDecode(key: key, salt1: salt1, salt2: salt2), trip))
                }
            }
            let n = TripSpec.add64(lo: lo, hi: hi, add: 7)
            lo = n.lo; hi = n.hi
        }
        return out
    }
}
