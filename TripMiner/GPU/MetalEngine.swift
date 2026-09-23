import Foundation
import Metal

/// Web版 GPUHelper + TripMinerApp.initGPU/autoOptimize に対応。
/// デバイス管理・パイプラインキャッシュ・スレッド数自動調整を担う。
final class MetalEngine {
    static let shared = MetalEngine()

    let device: MTLDevice?
    let queue: MTLCommandQueue?
    private var libraryCache: [String: MTLLibrary] = [:]

    var isAvailable: Bool { device != nil && queue != nil }

    init() {
        device = MTLCreateSystemDefaultDevice()
        queue = device?.makeCommandQueue(maxCommandBufferCount: 64)
    }

    // MARK: - ライブラリ生成

    /// ベースMSLソース + 生成matcher を結合してライブラリ化する。
    /// JS: GPUHelper.buildRegexWGSL に対応(#regex_matcher_code 置換)。
    func makeLibrary(baseSource: String, matcher: String, threadWidth: Int, key: String) throws -> MTLLibrary {
        let cacheKey = "\(key)-\(threadWidth)-\(matcher.hashValue)"
        if let lib = libraryCache[cacheKey] { return lib }
        var src = baseSource
            .replacingOccurrences(of: "#workgroup_size", with: "\(threadWidth)")
        // 生成matcherの注入: マーカーブロックがあれば置換、なければ旧プレースホルダ
        if let start = src.range(of: "//__REGEX_MATCHER_BEGIN__"),
           let end = src.range(of: "//__REGEX_MATCHER_END__", range: start.upperBound..<src.endIndex) {
            src.replaceSubrange(start.lowerBound..<end.upperBound, with: matcher)
        } else {
            src = src.replacingOccurrences(of: "#regex_matcher_code", with: matcher)
        }
        guard let device else { throw MetalError.noDevice }
        let lib = try device.makeLibrary(source: src, options: nil)
        libraryCache[cacheKey] = lib
        return lib
    }

    func makePipeline(library: MTLLibrary, function: String = "main") throws -> MTLComputePipelineState {
        guard let device else { throw MetalError.noDevice }
        guard let fn = library.makeFunction(name: function) else { throw MetalError.missingFunction(function) }
        return try device.makeComputePipelineState(function: fn)
    }

    // MARK: - 実行ヘルパー

    /// 1ディスパッチを実行し、GPU時間を返す。JS: mode.execute の計測部に対応。
    func dispatch(pipeline: MTLComputePipelineState, bindings: [MTLBuffer?], threadgroups: Int, threadsPerGroup: Int) throws -> Double {
        guard let queue else { throw MetalError.noDevice }
        guard let cmd = queue.makeCommandBuffer(),
              let enc = cmd.makeComputeCommandEncoder() else { throw MetalError.encodeFailed }
        let t0 = CFAbsoluteTimeGetCurrent()
        enc.setComputePipelineState(pipeline)
        for (i, buf) in bindings.enumerated() {
            if let buf { enc.setBuffer(buf, offset: 0, index: i) }
        }
        let tg = MTLSize(width: threadgroups, height: 1, depth: 1)
        let tp = MTLSize(width: threadsPerGroup, height: 1, depth: 1)
        enc.dispatchThreadgroups(tg, threadsPerThreadgroup: tp)
        enc.endEncoding()
        cmd.commit()
        cmd.waitUntilCompleted()
        if let err = cmd.error { throw MetalError.executionFailed(err.localizedDescription) }
        return (CFAbsoluteTimeGetCurrent() - t0) * 1000
    }

    func makeBuffer<T>(of type: T.Type, count: Int, options: MTLResourceOptions = .storageModeShared) -> MTLBuffer? {
        device?.makeBuffer(length: MemoryLayout<T>.stride * count, options: options)
    }

    /// 配列内容で初期化したバッファを作る
    func makeBuffer<T>(from array: [T], options: MTLResourceOptions = .storageModeShared) -> MTLBuffer? {
        guard let device, !array.isEmpty else { return nil }
        return array.withUnsafeBytes { bytes in
            device.makeBuffer(bytes: bytes.baseAddress!, length: bytes.count, options: options)
        }
    }

    func makeBuffer(bytes: UnsafeRawPointer, length: Int) -> MTLBuffer? {
        device?.makeBuffer(bytes: bytes, length: length, options: .storageModeShared)
    }

    // MARK: - 自動調整

    struct TuneResult { var threadgroups: Int; var threadWidth: Int }

    /// Web版 autoOptimize の Metal 版。平均100ms未満で最速の構成を選ぶ。
    func autoTune(
        candidates: [(threadgroups: Int, threadWidth: Int)] = [
            (32, 32), (32, 64), (32, 128), (64, 128),
            (128, 128), (256, 128), (256, 256), (512, 256),
            (1024, 256), (2048, 256), (4096, 256),
        ],
        measure: (Int, Int) throws -> Double,
        hashesPerIter: (Int, Int) -> Int,
        shouldStop: () -> Bool
    ) -> TuneResult {
        var best = TuneResult(threadgroups: 32, threadWidth: 32)
        var bestRate = 0.0
        for (tg, tw) in candidates {
            if shouldStop() { break }
            guard let dev = device, tg * tw <= 1_048_576 else { break }
            _ = dev.maxThreadsPerThreadgroup
            if tw > dev.maxThreadsPerThreadgroup { continue }
            do {
                var total = 0.0
                let iters = 5
                for _ in 0..<iters {
                    if shouldStop() { break }
                    total += try measure(tg, tw)
                }
                let avg = total / Double(iters)
                let rate = Double(hashesPerIter(tg, tw)) / (avg / 1000)
                if rate > bestRate, avg < 100 {
                    bestRate = rate
                    best = TuneResult(threadgroups: tg, threadWidth: tw)
                }
                if avg >= 300 { break }
            } catch {
                break
            }
        }
        return best
    }

    enum MetalError: Error {
        case noDevice
        case missingFunction(String)
        case encodeFailed
        case executionFailed(String)
    }
}
