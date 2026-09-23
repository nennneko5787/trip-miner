import Foundation
import Metal

/// 12桁(sha1)モード。Web版 ShaModeStrategy に対応。
/// hash パス → regex パスの2パス構成。Metal不可時はCPUフォールバック。
final class ShaMiner {
    private var hashPipeline: MTLComputePipelineState?
    private var regexPipeline: MTLComputePipelineState?
    private var inBuf, charMapBuf, paramsBuf, digestBuf, maskBuf: MTLBuffer?
    private(set) var laneCount = 0
    let batchCount = 32
    private var tuning: MetalEngine.TuneResult = .init(threadgroups: 32, threadWidth: 32)

    /// charMap uniform。JS: createShaCharMapUniformData
    static func charMapData() -> [UInt32] {
        var data = [UInt32](repeating: 0, count: 16 * 4 + 32 * 4)
        let chars = Array(TripSpec.alphabet12)
        for i in 0..<64 { data[i] = UInt32(chars[i].asciiValue ?? 0) }
        for i in 0..<64 {
            let a = Int(chars[i].asciiValue ?? 0)
            data[16 * 4 + a] = UInt32(i)
        }
        return data
    }

    static func encodeMessage(_ msg: String) -> [UInt32] {
        let norm = TripSpec.normalizeShaMessage(msg)
        let bytes = Array(norm.utf8)
        func w(_ i: Int) -> UInt32 {
            (UInt32(bytes[i]) << 24) | (UInt32(bytes[i + 1]) << 16) | (UInt32(bytes[i + 2]) << 8) | UInt32(bytes[i + 3])
        }
        return [w(0), w(4), w(8)]
    }

    func prepare(matcher: String, threadWidth: Int) throws {
        let engine = MetalEngine.shared
        guard engine.isAvailable else { return }
        guard let hashURL = Bundle.main.url(forResource: "ShaHash", withExtension: "metal"),
              let regexURL = Bundle.main.url(forResource: "ShaRegex", withExtension: "metal") else {
            throw MetalEngine.MetalError.missingFunction("Sha*.metal")
        }
        let hashSrc = try String(contentsOf: hashURL, encoding: .utf8)
        let regexSrc = try String(contentsOf: regexURL, encoding: .utf8)
        let hashLib = try engine.makeLibrary(baseSource: hashSrc, matcher: "", threadWidth: threadWidth, key: "sha-hash")
        let regexLib = try engine.makeLibrary(baseSource: regexSrc, matcher: matcher, threadWidth: threadWidth, key: "sha-regex")
        hashPipeline = try engine.makePipeline(library: hashLib)
        regexPipeline = try engine.makePipeline(library: regexLib)
    }

    struct MessageWire { var m0: UInt32; var m1: UInt32; var m2: UInt32; var pad: UInt32 }
    struct ParamsWire { var total: UInt32; var batch: UInt32; var count: UInt32; var pad: UInt32 }

    var outWords: Int { ((laneCount + 31) / 32) * batchCount }

    func allocate(threadgroups: Int, threadWidth: Int) throws {
        let engine = MetalEngine.shared
        guard engine.isAvailable, let device = engine.device else { return }
        laneCount = threadgroups * threadWidth
        tuning = .init(threadgroups: threadgroups, threadWidth: threadWidth)
        inBuf = device.makeBuffer(length: MemoryLayout<MessageWire>.stride, options: .storageModeShared)
        let cmap = Self.charMapData()
        charMapBuf = device.makeBuffer(bytes: cmap, length: cmap.count * 4, options: .storageModeShared)
        paramsBuf = device.makeBuffer(length: MemoryLayout<ParamsWire>.stride, options: .storageModeShared)
        digestBuf = device.makeBuffer(length: laneCount * batchCount * 3 * 4, options: .storageModeShared)
        maskBuf = device.makeBuffer(length: outWords * 4, options: .storageModeShared)
    }

    /// 2パス実行 → (経過ms, マスクワード列)
    func runBatch(seed: String) throws -> (elapsedMs: Double, masks: [UInt32]) {
        let engine = MetalEngine.shared
        guard let hashPipeline, let regexPipeline,
              let inBuf, let charMapBuf, let paramsBuf, let digestBuf, let maskBuf else {
            throw MetalEngine.MetalError.encodeFailed
        }
        let t0 = CFAbsoluteTimeGetCurrent()
        memset(maskBuf.contents(), 0, outWords * 4)
        for b in 0..<batchCount {
            let msg = TripSpec.incrementMessage12(seed, by: UInt32(laneCount * b))
            var w = Self.encodeMessage(msg)
            var mw = MessageWire(m0: w[0], m1: w[1], m2: w[2], pad: 0)
            memcpy(inBuf.contents(), &mw, MemoryLayout<MessageWire>.stride)
            var pw = ParamsWire(total: UInt32(laneCount), batch: UInt32(b), count: UInt32(batchCount), pad: 0)
            memcpy(paramsBuf.contents(), &pw, MemoryLayout<ParamsWire>.stride)
            _ = try engine.dispatch(pipeline: hashPipeline,
                                    bindings: [inBuf, charMapBuf, paramsBuf, digestBuf],
                                    threadgroups: tuning.threadgroups, threadsPerGroup: tuning.threadWidth)
        }
        var pw = ParamsWire(total: UInt32(laneCount), batch: 0, count: UInt32(batchCount), pad: 0)
        memcpy(paramsBuf.contents(), &pw, MemoryLayout<ParamsWire>.stride)
        let chunks = (laneCount + 31) / 32
        let regexGroups = (outWords + tuning.threadWidth - 1) / tuning.threadWidth
        _ = try engine.dispatch(pipeline: regexPipeline,
                                bindings: [digestBuf, paramsBuf, maskBuf],
                                threadgroups: regexGroups, threadsPerGroup: tuning.threadWidth)
        _ = chunks
        let ptr = maskBuf.contents().bindMemory(to: UInt32.self, capacity: outWords)
        let masks = Array(UnsafeBufferPointer(start: ptr, count: outWords))
        return ((CFAbsoluteTimeGetCurrent() - t0) * 1000, masks)
    }

    /// マスク → (キー表示, トリップ)。JS decode に対応
    func decode(masks: [UInt32], seed: String) -> [(key: String, trip: String)] {
        var out: [(String, String)] = []
        let chunks = (laneCount + 31) / 32
        for batch in 0..<batchCount {
            for i in 0..<chunks {
                var mask = masks[batch * chunks + i]
                while mask != 0 {
                    let lsb = mask & (~mask &+ 1)
                    let lane = lsb.trailingZeroBitCount
                    let idx = i * 32 + lane
                    if idx < laneCount {
                        let msg = TripSpec.incrementMessage12(seed, by: UInt32(batch * laneCount + idx))
                        out.append(("#" + msg, ReferenceImpl.sha12(msg)))
                    }
                    mask &= mask &- 1
                }
            }
        }
        return out
    }

    /// CPUフォールバックで1バッチ探索する
    func searchCPU(seed: String, count: Int, match: (String) -> Bool) -> [(key: String, trip: String)] {
        var out: [(String, String)] = []
        for i in 0..<count {
            let msg = TripSpec.incrementMessage12(seed, by: UInt32(i))
            let trip = ReferenceImpl.sha12(msg)
            if match(trip) { out.append(("#" + msg, trip)) }
        }
        return out
    }
}
