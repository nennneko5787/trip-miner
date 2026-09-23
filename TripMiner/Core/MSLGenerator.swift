import Foundation

/// Web版 wgsl-generator.js の Swift/MSL 移植。
/// 最適化済み論理AST → `uint regex_match(...)` の MSL ソースを生成する。
enum MSLGenerator {
    /// 10桁用 FP転置テーブル (JS と同一)
    static let fp: [Int] = [
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25,
        32, 0, 40, 8, 48, 16, 56, 24,
    ]

    struct Gen {
        var mode: Int // 10 or 12
        var statements: [String] = []
        var counter = 0

        mutating func newVar() -> String {
            defer { counter += 1 }
            return "v\(counter)"
        }

        /// ビット参照式。常に0の範囲は nil。JS: getBit
        func bit(charIdx: Int, bitIdx: Int) -> String? {
            if mode == 10 {
                let p = charIdx * 6 + 6 + bitIdx
                guard p < 64 else { return nil }
                return "b[\(MSLGenerator.fp[p])]"
            } else {
                return "b[\(charIdx * 6 + bitIdx)]"
            }
        }

        mutating func compile(_ node: LogicOptimizer.Node) -> String {
            switch node {
            case .t: return "0xFFFFFFFFu"
            case .f: return "0u"
            case let .lit(charIndex, mask):
                let minterms = (0..<64).filter { (mask >> UInt64($0)) & 1 == 1 }
                let pis = MSLGenerator.minimize(minterms: minterms)
                if pis.isEmpty { return "0u" }
                if pis == ["------"] { return "0xFFFFFFFFu" }
                var exprs: [String] = []
                for pi in pis {
                    var terms: [String] = []
                    var dead = false
                    let bits = Array(pi)
                    for i in 0..<6 {
                        let b = bit(charIdx: charIndex, bitIdx: i)
                        if bits[i] == "0" {
                            if let b { terms.append("~\(b)") }
                        } else if bits[i] == "1" {
                            guard let b else { dead = true; break }
                            terms.append(b)
                        }
                    }
                    if dead { continue }
                    exprs.append(terms.isEmpty ? "0xFFFFFFFFu" : terms.count == 1 ? terms[0] : "(" + terms.joined(separator: " & ") + ")")
                }
                if exprs.isEmpty { return "0u" }
                if exprs.contains("0xFFFFFFFFu") { return "0xFFFFFFFFu" }
                if exprs.count == 1 { return exprs[0] }
                return "(" + exprs.joined(separator: " |\n    ") + ")"
            case let .eq(a, b):
                var terms: [String] = []
                for i in 0..<6 {
                    let x = bit(charIdx: a, bitIdx: i), y = bit(charIdx: b, bitIdx: i)
                    if x == nil, y == nil { continue }
                    else if x == nil { terms.append(y!) }
                    else if y == nil { terms.append(x!) }
                    else { terms.append("(\(x!) ^ \(y!))") }
                }
                if terms.isEmpty { return "0xFFFFFFFFu" }
                return "~(\(terms.joined(separator: " | ")))"
            case let .and(ns), let .or(ns):
                let op = {
                    if case .and = node { return " & " } else { return " | " }
                }()
                let name = newVar()
                statements.append("uint \(name) = \(ns.map { compile($0) }.joined(separator: op + "\n    "));")
                return name
            }
        }
    }

    /// Quine-McCluskey (最大6変数) + 貪欲セットカバー。JS: minimizeMinterms
    static func minimize(minterms: [Int]) -> [String] {
        if minterms.isEmpty { return [] }
        if minterms.count == 64 { return ["------"] }
        var terms = minterms.map { String($0, radix: 2).pad(to: 6) }
        var primes = Set<String>()
        while !terms.isEmpty {
            var next = Set<String>()
            var merged = Set<String>()
            for i in 0..<terms.count {
                for j in (i + 1)..<terms.count {
                    let a = Array(terms[i]), b = Array(terms[j])
                    var diff = 0, idx = -1
                    for k in 0..<6 where a[k] != b[k] { diff += 1; idx = k }
                    if diff == 1 {
                        var c = a; c[idx] = "-"
                        next.insert(String(c))
                        merged.insert(terms[i]); merged.insert(terms[j])
                    }
                }
            }
            for t in terms where !merged.contains(t) { primes.insert(t) }
            terms = Array(next)
        }
        var uncovered = Set(minterms)
        var selected: [String] = []
        let piList = Array(primes)
        while !uncovered.isEmpty {
            var best: String? = nil, bestCover: [Int] = []
            for pi in piList where !selected.contains(pi) {
                let cover = uncovered.filter { m in
                    let s = String(m, radix: 2).pad(to: 6)
                    for (p, q) in zip(pi, s) where p != "-" && p != q { return false }
                    return true
                }
                if cover.count > bestCover.count { bestCover = cover; best = pi }
            }
            guard let b = best else { break }
            selected.append(b)
            for m in bestCover { uncovered.remove(m) }
        }
        return selected
    }

    /// 公開API。JS: generateWGSL に対応
    static func generate(ast: LogicOptimizer.Node, mode: Int) -> String {
        var gen = Gen(mode: mode)
        let result = gen.compile(ast)
        // Crypt.metal / ShaRegex.metal 側の宣言と合わせる
        var code = "inline uint regex_match(thread uint *b) {\n"
        for s in gen.statements { code += "  \(s)\n" }
        code += "  return \(result);\n}\n"
        return code
    }
}

private extension String {
    func pad(to n: Int) -> String {
        String(repeating: "0", count: max(0, n - count)) + self
    }
}
