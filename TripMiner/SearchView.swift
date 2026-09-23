import SwiftUI

/// 状態機械。JS TripMinerApp.state に対応
enum MinerState: String {
    case stopped = "停止中"
    case compiling = "正規表現コンパイル中..."
    case optimizing = "並列数最適化中..."
    case mining = "厳選中"
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

    private var stopRequested = false
    private let crypt = CryptMiner()
    private let sha = ShaMiner()
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
        stopRequested = true
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
        stopRequested = false
        state = .compiling
        updateStatus()
        Task { await run() }
    }

    // MARK: - 探索ループ

    private func run() async {
        let settings = settings
        let pattern: String
        do {
            pattern = SearchValidator.formatRegex(settings)
            let cases = try RegexCore.compile(pattern: pattern, targetLen: settings.digit)
            let optimized = LogicOptimizer.optimize(cases: cases)
            let matcher = MSLGenerator.generate(ast: optimized, mode: settings.digit)
            state = .optimizing
            updateStatus()
            if settings.digit == 10 {
                try await runCrypt(pattern: pattern, matcher: matcher, settings: settings)
            } else {
                try await runSha(pattern: pattern, matcher: matcher, settings: settings)
            }
        } catch {
            errorMessage = "エラー: \(error.localizedDescription)"
            state = .stopped
            updateStatus()
        }
        if state != .stopped {
            state = .stopped
            updateStatus()
        }
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

    private func runCrypt(pattern: String, matcher: String, settings: SearchSettings) async throws {
        resetStats()
        let regex = try NSRegularExpression(pattern: pattern)
        // GPU初期化・実行に失敗したらCPUにフォールバックする
        if MetalEngine.shared.isAvailable {
            do {
                try await runCryptGPU(matcher: matcher, settings: settings)
                return
            } catch {
                if stopRequested { return }
                errorMessage = "GPU初期化に失敗したためCPUで継続します"
            }
        }
        if stopRequested { return }
        await runCryptCPU(regex: regex)
    }

    /// GPUパス。失敗時は throw し、呼び出し側がCPUにフォールバックする
    private func runCryptGPU(matcher: String, settings: SearchSettings) async throws {
        let engine = MetalEngine.shared
        try crypt.prepare(matcher: matcher, threadWidth: 128)
            // 自動調整
            let tune = engine.autoTune(
                measure: { tg, tw in
                    try self.crypt.allocate(threadgroups: tg, threadWidth: tw)
                    let seed = TripSpec.randomSeed10()
                    let (ms, masks) = try self.crypt.runBatch(seedLo: seed.lo, seedHi: seed.hi)
                    let found = self.crypt.decode(masks: masks, seedLo: seed.lo, seedHi: seed.hi)
                    self.appendMatches(found.map { "◆\($0.trip) : ##\($0.key)" })
                    self.noteHashes(TripSpec.hashesPerIteration10(workgroups: tg, workgroupSize: tw))
                    return ms
                },
                hashesPerIter: { TripSpec.hashesPerIteration10(workgroups: $0, workgroupSize: $1) },
                shouldStop: { self.stopRequested })
            if stopRequested { return }
            try crypt.allocate(threadgroups: tune.threadgroups, threadWidth: tune.threadWidth)
            try crypt.prepare(matcher: matcher, threadWidth: tune.threadWidth)
            state = .mining
            var seed = TripSpec.randomSeed10()
            let step = TripSpec.step10(workgroups: tune.threadgroups, workgroupSize: tune.threadWidth)
            while !stopRequested {
                let (ms, masks) = try crypt.runBatch(seedLo: seed.lo, seedHi: seed.hi)
                _ = ms
                let found = crypt.decode(masks: masks, seedLo: seed.lo, seedHi: seed.hi)
                appendMatches(found.map { "◆\($0.trip) : ##\($0.key)" })
                noteHashes(TripSpec.hashesPerIteration10(workgroups: tune.threadgroups, workgroupSize: tune.threadWidth))
                seed = TripSpec.advanceSeed10(lo: seed.lo, hi: seed.hi, step: step)
                await Task.yield()
            }
    }

    private func runCryptCPU(regex: NSRegularExpression) async {
        func isMatch(_ trip: String) -> Bool {
            regex.firstMatch(in: trip, range: NSRange(trip.startIndex..., in: trip)) != nil
        }
        state = .mining
        var seed = TripSpec.randomSeed10()
        while !stopRequested {
            let found = crypt.searchCPU(seedLo: seed.lo, seedHi: seed.hi, count: 4096, match: isMatch)
            appendMatches(found.map { "◆\($0.trip) : ##\($0.key)" })
            noteHashes(4096)
            seed = TripSpec.advanceSeed10(lo: seed.lo, hi: seed.hi, step: 4096 * 7)
            await Task.yield()
        }
    }

    // MARK: 12桁

    private func runSha(pattern: String, matcher: String, settings: SearchSettings) async throws {
        resetStats()
        let regex = try NSRegularExpression(pattern: pattern)
        // GPU初期化・実行に失敗したらCPUにフォールバックする
        if MetalEngine.shared.isAvailable {
            do {
                try await runShaGPU(matcher: matcher, settings: settings)
                return
            } catch {
                if stopRequested { return }
                errorMessage = "GPU初期化に失敗したためCPUで継続します"
            }
        }
        if stopRequested { return }
        await runShaCPU(regex: regex)
    }

    /// GPUパス。失敗時は throw し、呼び出し側がCPUにフォールバックする
    private func runShaGPU(matcher: String, settings: SearchSettings) async throws {
        let engine = MetalEngine.shared
        try sha.prepare(matcher: matcher, threadWidth: 128)
            let tune = engine.autoTune(
                measure: { tg, tw in
                    try self.sha.allocate(threadgroups: tg, threadWidth: tw)
                    let seed = TripSpec.randomMessage12()
                    let (ms, masks) = try self.sha.runBatch(seed: seed)
                    let found = self.sha.decode(masks: masks, seed: seed)
                    self.appendMatches(found.map { "◆\($0.trip) : #\($0.key)" })
                    self.noteHashes(TripSpec.hashesPerIteration12(workgroups: tg, workgroupSize: tw))
                    return ms
                },
                hashesPerIter: { TripSpec.hashesPerIteration12(workgroups: $0, workgroupSize: $1) },
                shouldStop: { self.stopRequested })
            if stopRequested { return }
            try sha.allocate(threadgroups: tune.threadgroups, threadWidth: tune.threadWidth)
            try sha.prepare(matcher: matcher, threadWidth: tune.threadWidth)
            state = .mining
            var seed = TripSpec.randomMessage12()
            let step = TripSpec.step12(workgroups: tune.threadgroups, workgroupSize: tune.threadWidth)
            while !stopRequested {
                let (ms, masks) = try sha.runBatch(seed: seed)
                _ = ms
                let found = sha.decode(masks: masks, seed: seed)
                appendMatches(found.map { "◆\($0.trip) : #\($0.key)" })
                noteHashes(TripSpec.hashesPerIteration12(workgroups: tune.threadgroups, workgroupSize: tune.threadWidth))
                seed = TripSpec.incrementMessage12(seed, by: step * UInt32(sha.batchCount))
                await Task.yield()
            }
    }

    private func runShaCPU(regex: NSRegularExpression) async {
        func isMatch(_ trip: String) -> Bool {
            regex.firstMatch(in: trip, range: NSRange(trip.startIndex..., in: trip)) != nil
        }
        state = .mining
        var seed = TripSpec.randomMessage12()
        while !stopRequested {
            let found = sha.searchCPU(seed: seed, count: 4096, match: isMatch)
            appendMatches(found.map { "◆\($0.trip) : #\($0.key)" })
            noteHashes(4096)
            seed = TripSpec.incrementMessage12(seed, by: 4096)
            await Task.yield()
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
                    Text("ヒットしたトリップ")
                    Spacer()
                    Button("クリア") { vm.clear() }
                }) {
                    if vm.results.isEmpty {
                        Text("—").foregroundColor(.secondary)
                    } else {
                        ForEach(Array(vm.results.suffix(200).enumerated()), id: \.offset) { _, line in
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
