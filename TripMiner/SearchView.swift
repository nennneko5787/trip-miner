import SwiftUI

/// 状態機械。JS TripMinerApp.state に対応
enum MinerState: String {
    case stopped = "停止中"
    case compiling = "正規表現コンパイル中..."
    case optimizing = "並列数最適化中..."
    case mining = "厳選中"
}

/// 停止フラグ。メインスレッドと計算スレッドで共有する
final class StopFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var _stopped = false
    var stopped: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _stopped
    }
    func stop() {
        lock.lock()
        defer { lock.unlock() }
        _stopped = true
    }
}

@MainActor
final class MinerViewModel: ObservableObject {
    // 設定 (Web版フォームに対応)
    @Published var digit = 10
    @Published var useRegex = false
    @Published var matchType: SearchSettings.MatchType = .prefix
    @Published var target = ""
    // 状態
    @Published var state: MinerState = .stopped
    @Published var errorMessage = ""
    @Published var statusText = "状態: 停止中"
    @Published var results: [String] = []
    @Published var matchCount = 0
    @Published var showHelp = false

    private var computeTask: Task<Void, Never>?
    private var stopFlag = StopFlag()
    private var totalHashes = 0
    private var startTime: CFAbsoluteTime = 0
    private var hashes5s = 0
    private var last5sTime: CFAbsoluteTime = 0
    private var lastAvg5s = 0.0
    private var iter = 0

    var isMining: Bool { state != .stopped }

    var settings: SearchSettings {
        SearchSettings(digit: digit, useRegex: useRegex, matchType: matchType, target: target)
    }

    var validationError: String? { SearchValidator.validate(settings) }
    var canStart: Bool { validationError == nil }

    func compiledDisplay() -> String { SearchValidator.displayRegex(settings) }

    // MARK: - 操作

    func toggle() {
        if isMining { stop() }
        else { start() }
    }

    func stop() {
        stopFlag.stop()
        computeTask?.cancel()
        computeTask = nil
        state = .stopped
        updateStatus()
    }

    func clear() {
        results.removeAll()
        matchCount = 0
    }

    func start() {
        guard !isMining else { return }
        if let err = validationError {
            errorMessage = err
            return
        }
        errorMessage = ""
        let flag = StopFlag()
        stopFlag = flag
        state = .compiling
        updateStatus()
        // 計算はバックグラウンドで回す(メインスレッドを塞がない)
        let settings = settings
        computeTask = Task.detached(priority: .userInitiated) { [weak self] in
            guard let self else { return }
            await self.runBackground(settings: settings, stop: flag)
        }
    }

    // MARK: - 探索ループ(バックグラウンド駆動)

    /// 全体進行。バックグラウンドスレッドで実行し、UI更新だけMainActorに委譲する
    nonisolated func runBackground(settings: SearchSettings, stop: StopFlag) async {
        let pattern = SearchValidator.formatRegex(settings)
        let matcher: String
        do {
            let cases = try RegexCore.compile(pattern: pattern, targetLen: settings.digit)
            matcher = MSLGenerator.generate(ast: LogicOptimizer.optimize(cases: cases), mode: settings.digit)
        } catch {
            await self.failBackground("コンパイルエラー: \(error.localizedDescription)")
            return
        }
        await self.setState(.optimizing)
        if MetalEngine.shared.isAvailable {
            do {
                if settings.digit == 10 {
                    try await self.runCryptGPUBackground(matcher: matcher, stop: stop)
                } else {
                    try await self.runShaGPUBackground(matcher: matcher, stop: stop)
                }
                await self.finishBackground()
                return
            } catch {
                if stop.stopped {
                    await self.finishBackground()
                    return
                }
                await self.noteFallback("GPU初期化失敗(\(error.localizedDescription))のためCPUで継続します")
            }
        }
        if stop.stopped {
            await self.finishBackground()
            return
        }
        if settings.digit == 10 {
            await self.runCryptCPUBackground(pattern: pattern, stop: stop)
        } else {
            await self.runShaCPUBackground(pattern: pattern, stop: stop)
        }
        await self.finishBackground()
    }

    // MARK: MainActor側の小物(UI更新専用)

    private func setState(_ s: MinerState) {
        state = s
        updateStatus()
    }

    private func beginMining() {
        resetStats()
        state = .mining
        updateStatus()
    }

    private func finishBackground() {
        state = .stopped
        updateStatus()
    }

    private func failBackground(_ msg: String) {
        errorMessage = msg
        state = .stopped
        updateStatus()
    }

    private func noteFallback(_ msg: String) {
        errorMessage = msg
    }

    /// バックグラウンドからの定期反映
    private func flush(lines: [String], hashes: Int) {
        if state == .stopped { return }
        appendMatches(lines)
        noteHashes(hashes)
        updateStatus()
    }

    private func resetStats() {
        totalHashes = 0; hashes5s = 0; iter = 0; matchCount = 0
        startTime = CFAbsoluteTimeGetCurrent()
        last5sTime = startTime
        lastAvg5s = 0
    }

    private func noteHashes(_ n: Int) {
        iter += 1
        totalHashes += n
        hashes5s += n
        let now = CFAbsoluteTimeGetCurrent()
        if now - last5sTime >= 5 {
            lastAvg5s = Double(hashes5s) / (now - last5sTime)
            hashes5s = 0
            last5sTime = now
        }
        if iter % 10 == 0 { updateStatus() }
    }

    private func appendMatches(_ lines: [String]) {
        guard !lines.isEmpty else { return }
        matchCount += lines.count
        results.append(contentsOf: lines)
        if results.count > 5000 { results.removeFirst(results.count - 5000) }
    }

    private func updateStatus() {
        let mode = digit == 10 ? "10桁モード" : "12桁モード"
        let elapsed = startTime > 0 ? CFAbsoluteTimeGetCurrent() - startTime : 0
        statusText = [
            state.rawValue,
            "動作モード: \(mode)",
            "直近5秒平均: \(SearchValidator.formatUnit(lastAvg5s)) tripcodes/sec",
            "総トリップ数: \(SearchValidator.formatUnit(Double(totalHashes)))",
            "総実行時間: \(String(format: "%.2f", elapsed)) sec",
            "累計一致数: \(matchCount)",
        ].joined(separator: "\n")
    }

    // MARK: 10桁

    nonisolated func runCryptGPUBackground(matcher: String, stop: StopFlag) async throws {
        let engine = MetalEngine.shared
        let crypt = CryptMiner()
        try crypt.prepare(matcher: matcher, threadWidth: 128)
        // 自動調整(測定中のヒットも拾う)
        var tuneLines: [String] = []
        var tuneHashes = 0
        let tune = engine.autoTune(
            measure: { tg, tw in
                if stop.stopped { throw CancellationError() }
                try crypt.allocate(threadgroups: tg, threadWidth: tw)
                let seed = TripSpec.randomSeed10()
                let (ms, masks) = try crypt.runBatch(seedLo: seed.lo, seedHi: seed.hi)
                tuneLines += crypt.decode(masks: masks, seedLo: seed.lo, seedHi: seed.hi).map { "◆\($0.trip) : ##\($0.key)" }
                tuneHashes += TripSpec.hashesPerIteration10(workgroups: tg, workgroupSize: tw)
                return ms
            },
            hashesPerIter: { TripSpec.hashesPerIteration10(workgroups: $0, workgroupSize: $1) },
            shouldStop: { stop.stopped })
        if stop.stopped { return }
        try crypt.allocate(threadgroups: tune.threadgroups, threadWidth: tune.threadWidth)
        try crypt.prepare(matcher: matcher, threadWidth: tune.threadWidth)
        await self.beginMining()
        await self.flush(lines: tuneLines, hashes: tuneHashes)
        var seed = TripSpec.randomSeed10()
        let step = TripSpec.step10(workgroups: tune.threadgroups, workgroupSize: tune.threadWidth)
        let perIter = TripSpec.hashesPerIteration10(workgroups: tune.threadgroups, workgroupSize: tune.threadWidth)
        var pendingLines: [String] = []
        var pendingHashes = 0
        var lastFlush = CFAbsoluteTimeGetCurrent()
        while !stop.stopped {
            let (_, masks) = try crypt.runBatch(seedLo: seed.lo, seedHi: seed.hi)
            pendingLines += crypt.decode(masks: masks, seedLo: seed.lo, seedHi: seed.hi).map { "◆\($0.trip) : ##\($0.key)" }
            pendingHashes += perIter
            seed = TripSpec.advanceSeed10(lo: seed.lo, hi: seed.hi, step: step)
            let now = CFAbsoluteTimeGetCurrent()
            if (!pendingLines.isEmpty && now - lastFlush > 0.15) || (pendingHashes > 0 && now - lastFlush > 0.5) || pendingLines.count > 400 {
                await self.flush(lines: pendingLines, hashes: pendingHashes)
                pendingLines = []
                pendingHashes = 0
                lastFlush = now
            }
        }
        if !pendingLines.isEmpty || pendingHashes > 0 {
            await self.flush(lines: pendingLines, hashes: pendingHashes)
        }
    }

    nonisolated func runCryptCPUBackground(pattern: String, stop: StopFlag) async {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return }
        let crypt = CryptMiner()
        await self.beginMining()
        var seed = TripSpec.randomSeed10()
        var pendingLines: [String] = []
        var pendingHashes = 0
        var lastFlush = CFAbsoluteTimeGetCurrent()
        while !stop.stopped {
            let found = crypt.searchCPU(seedLo: seed.lo, seedHi: seed.hi, count: 8192, match: { trip in
                regex.firstMatch(in: trip, range: NSRange(trip.startIndex..., in: trip)) != nil
            })
            pendingLines += found.map { "◆\($0.trip) : ##\($0.key)" }
            pendingHashes += 8192
            seed = TripSpec.advanceSeed10(lo: seed.lo, hi: seed.hi, step: 8192 * 7)
            let now = CFAbsoluteTimeGetCurrent()
            if (!pendingLines.isEmpty && now - lastFlush > 0.15) || (pendingHashes > 0 && now - lastFlush > 0.5) || pendingLines.count > 400 {
                await self.flush(lines: pendingLines, hashes: pendingHashes)
                pendingLines = []
                pendingHashes = 0
                lastFlush = now
            }
        }
        if !pendingLines.isEmpty || pendingHashes > 0 {
            await self.flush(lines: pendingLines, hashes: pendingHashes)
        }
    }

    // MARK: 12桁

    nonisolated func runShaGPUBackground(matcher: String, stop: StopFlag) async throws {
        let engine = MetalEngine.shared
        let sha = ShaMiner()
        try sha.prepare(matcher: matcher, threadWidth: 128)
        var tuneLines: [String] = []
        var tuneHashes = 0
        let tune = engine.autoTune(
            measure: { tg, tw in
                if stop.stopped { throw CancellationError() }
                try sha.allocate(threadgroups: tg, threadWidth: tw)
                let seed = TripSpec.randomMessage12()
                let (ms, masks) = try sha.runBatch(seed: seed)
                tuneLines += sha.decode(masks: masks, seed: seed).map { "◆\($0.trip) : #\($0.key)" }
                tuneHashes += TripSpec.hashesPerIteration12(workgroups: tg, workgroupSize: tw)
                return ms
            },
            hashesPerIter: { TripSpec.hashesPerIteration12(workgroups: $0, workgroupSize: $1) },
            shouldStop: { stop.stopped })
        if stop.stopped { return }
        try sha.allocate(threadgroups: tune.threadgroups, threadWidth: tune.threadWidth)
        try sha.prepare(matcher: matcher, threadWidth: tune.threadWidth)
        await self.beginMining()
        await self.flush(lines: tuneLines, hashes: tuneHashes)
        var seed = TripSpec.randomMessage12()
        let step = TripSpec.step12(workgroups: tune.threadgroups, workgroupSize: tune.threadWidth)
        let perIter = TripSpec.hashesPerIteration12(workgroups: tune.threadgroups, workgroupSize: tune.threadWidth)
        var pendingLines: [String] = []
        var pendingHashes = 0
        var lastFlush = CFAbsoluteTimeGetCurrent()
        while !stop.stopped {
            let (_, masks) = try sha.runBatch(seed: seed)
            pendingLines += sha.decode(masks: masks, seed: seed).map { "◆\($0.trip) : #\($0.key)" }
            pendingHashes += perIter
            seed = TripSpec.incrementMessage12(seed, by: step * UInt32(sha.batchCount))
            let now = CFAbsoluteTimeGetCurrent()
            if (!pendingLines.isEmpty && now - lastFlush > 0.15) || (pendingHashes > 0 && now - lastFlush > 0.5) || pendingLines.count > 400 {
                await self.flush(lines: pendingLines, hashes: pendingHashes)
                pendingLines = []
                pendingHashes = 0
                lastFlush = now
            }
        }
        if !pendingLines.isEmpty || pendingHashes > 0 {
            await self.flush(lines: pendingLines, hashes: pendingHashes)
        }
    }

    nonisolated func runShaCPUBackground(pattern: String, stop: StopFlag) async {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return }
        let sha = ShaMiner()
        await self.beginMining()
        var seed = TripSpec.randomMessage12()
        var pendingLines: [String] = []
        var pendingHashes = 0
        var lastFlush = CFAbsoluteTimeGetCurrent()
        while !stop.stopped {
            let seedCopy = seed
            let found = sha.searchCPU(seed: seedCopy, count: 8192, match: { trip in
                regex.firstMatch(in: trip, range: NSRange(trip.startIndex..., in: trip)) != nil
            })
            pendingLines += found.map { "◆\($0.trip) : #\($0.key)" }
            pendingHashes += 8192
            seed = TripSpec.incrementMessage12(seed, by: 8192)
            let now = CFAbsoluteTimeGetCurrent()
            if (!pendingLines.isEmpty && now - lastFlush > 0.15) || (pendingHashes > 0 && now - lastFlush > 0.5) || pendingLines.count > 400 {
                await self.flush(lines: pendingLines, hashes: pendingHashes)
                pendingLines = []
                pendingHashes = 0
                lastFlush = now
            }
        }
        if !pendingLines.isEmpty || pendingHashes > 0 {
            await self.flush(lines: pendingLines, hashes: pendingHashes)
        }
    }
}

// MARK: - View

struct SearchView: View {
    @StateObject private var vm = MinerViewModel()

    var body: some View {
        NavigationStack {
            Form {
                Section("桁数") {
                    Picker("", selection: $vm.digit) {
                        Text("10桁").tag(10)
                        Text("12桁").tag(12)
                    }
                    .pickerStyle(.segmented)
                    .disabled(vm.isMining)
                }
                Section("正規表現") {
                    Picker("", selection: $vm.useRegex) {
                        Text("なし").tag(false)
                        Text("あり").tag(true)
                    }
                    .pickerStyle(.segmented)
                    .disabled(vm.isMining)
                    if vm.useRegex {
                        Menu("テンプレート: \(templateName())") {
                            ForEach(SearchValidator.templates, id: \.pattern) { t in
                                Button("\(t.name): \(t.pattern)") { vm.target = t.pattern }
                            }
                        }
                        .disabled(vm.isMining)
                    } else {
                        Picker("条件", selection: $vm.matchType) {
                            Text("前方一致").tag(SearchSettings.MatchType.prefix)
                            Text("後方一致").tag(SearchSettings.MatchType.suffix)
                            Text("部分一致").tag(SearchSettings.MatchType.partial)
                        }
                        .disabled(vm.isMining)
                    }
                }
                Section("ターゲット") {
                    TextField("検索パターンを入力", text: $vm.target)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .font(.system(.body, design: .monospaced))
                        .disabled(vm.isMining)
                    Text(vm.compiledDisplay())
                        .font(.system(.caption, design: .monospaced))
                        .padding(4)
                        .background(Color(.systemGray5))
                        .cornerRadius(4)
                    if !vm.errorMessage.isEmpty {
                        Text(vm.errorMessage).foregroundColor(.red).font(.caption)
                    } else if let err = vm.validationError, !vm.target.isEmpty {
                        Text(err).foregroundColor(.red).font(.caption)
                    }
                }
                Section("状態") {
                    Text(vm.statusText)
                        .font(.system(.caption, design: .monospaced))
                }
                Section {
                    Button(vm.isMining ? "停止" : "厳選開始") { vm.toggle() }
                        .disabled(!vm.isMining && !vm.canStart)
                    Button("使い方") { vm.showHelp = true }
                }
                Section(header: HStack {
                    Text("ヒットしたトリップ(最新30件)")
                    Spacer()
                    Button("クリア") { vm.clear() }
                }) {
                    if vm.results.isEmpty {
                        Text("—").foregroundColor(.secondary)
                    } else {
                        ForEach(Array(vm.results.suffix(30).enumerated()), id: \.offset) { _, line in
                            Text(line)
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                        }
                    }
                }
            }
            .navigationTitle("新トリップ検索機")
            .sheet(isPresented: $vm.showHelp) { HelpView() }
        }
    }

    private func templateName() -> String {
        SearchValidator.templates.first { $0.pattern == vm.target }?.name ?? "手動入力"
    }
}

struct HelpView: View {
    var body: some View {
        NavigationStack {
            List {
                Section("基本操作") {
                    Text("1. 桁数: 10桁か12桁を選ぶ")
                    Text("2. 正規表現: あり/なしを選ぶ。典型パターンはテンプレートから")
                    Text("3. 条件: 正規表現なし時は前方/後方/部分一致を選ぶ")
                    Text("4. ターゲット: 検索文字を入力(4桁以上目安)")
                    Text("5. 厳選開始: 探索を開始する")
                }
                Section("正規表現") {
                    Text(". 任意の1文字")
                    Text("[Ab]/[0-9] 指定文字のいずれか")
                    Text("? 直前0〜1回 / * 0回以上 / + 1回以上")
                    Text("{3}/{2,4} 回数指定")
                    Text("( ) グループ / (A|B) 選択 / \\2 後方参照")
                }
                Section("特長") {
                    Text("Metal GPU探索(iPhone最速狙い)。10桁は生キー・12桁はSHA-1。独自正規表現エンジンをMSLにコンパイルして判定する。")
                }
            }
            .navigationTitle("使い方")
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}
