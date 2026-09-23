import Foundation

/// Web版 regex-core.js の Swift 移植。
/// 64種文字を UInt64 マスクで表現し、候補長の分配・等価制約を列挙する。
enum RegexCore {
    static let alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    static let fullMask: UInt64 = UInt64.max

    static func maskFromChars(_ chars: [Character]) -> UInt64 {
        var mask: UInt64 = 0
        for ch in chars {
            if let i = alphabet.firstIndex(of: ch) {
                mask |= (1 << UInt64(alphabet.distance(from: alphabet.startIndex, to: i)))
            }
        }
        return mask
    }

    static func maskToChars(_ mask: UInt64) -> [Character] {
        let chars = Array(alphabet)
        return chars.indices.filter { (mask >> UInt64($0)) & 1 == 1 }.map { chars[$0] }
    }

    static func popcount(_ mask: UInt64) -> UInt64 {
        var m = mask, c: UInt64 = 0
        while m != 0 { m &= m &- 1; c += 1 }
        return c
    }

    // MARK: - AST

    indirect enum Node {
        case domain(mask: UInt64)
        case anchorStart, anchorEnd
        case backRef(index: Int)
        case capture(index: Int, node: Node)
        case alternate(nodes: [Node])
        case concat(nodes: [Node])
        case repeatNode(node: Node, min: Int, max: Int)

        var lengthSet: Set<Int> {
            switch self {
            case .domain: return [1]
            case .anchorStart, .anchorEnd: return [0]
            case .backRef: return [0] // 呼び出し側でグループ長に置換
            case let .capture(_, n): return n.lengthSet
            case let .alternate(ns):
                return ns.reduce(Set<Int>()) { $0.union($1.lengthSet) }
            case let .concat(ns):
                return ns.reduce(Set([0])) { combineSets($0, $1.lengthSet, max: Int.max) }
            case let .repeatNode(n, min, max):
                var out = Set<Int>()
                for k in min...max {
                    var dp = Set([0])
                    for _ in 0..<k { dp = combineSets(dp, n.lengthSet, max: Int.max) }
                    out.formUnion(dp)
                }
                return out
            }
        }
    }

    struct Instruction: Hashable {
        enum Op { case domain, captureStart, captureEnd, backref }
        var op: Op
        var mask: UInt64 = 0
        var index: Int = 0
        var len: Int = 0
    }

    struct Evaluation {
        var domains: [UInt64]
        var equalities: [(Int, Int)]
    }

    // MARK: - Parser

    final class Parser {
        let pattern: [Character]
        let maxLen: Int
        var pos = 0
        var groupIndex = 1
        // 後方参照の長さ解決用: グループ番号 → 取り得る長さ集合
        var groupLenMap: [Int: Set<Int>] = [:]

        init(pattern: String, maxLen: Int) {
            self.pattern = Array(pattern)
            self.maxLen = maxLen
        }

        func parse() throws -> Node {
            let node = try parseAlt()
            guard eof else { throw RegexError.syntax("Unexpected token at \(pos)") }
            return analyzeLength(node)
        }

        // makeLengthInfo 相当: Repeat 上限を maxLen で丸め、Capture/BackRef の長さを記録
        func analyzeLength(_ node: Node) -> Node {
            switch node {
            case .domain, .anchorStart, .anchorEnd, .backRef:
                if case let .backRef(i) = node {
                    void(i)
                }
                return node
            case let .capture(i, n):
                let inner = analyzeLength(n)
                let prev = groupLenMap[i] ?? []
                groupLenMap[i] = prev.union(inner.lengthSet)
                return .capture(index: i, node: inner)
            case let .alternate(ns):
                var merged: [Int: Set<Int>] = [:]
                let out = ns.map { branch -> Node in
                    let saved = groupLenMap
                    let analyzed = analyzeLength(branch)
                    for (k, v) in groupLenMap {
                        merged[k] = (merged[k] ?? []).union(v)
                    }
                    groupLenMap = saved
                    return analyzed
                }
                for (k, v) in merged { groupLenMap[k] = v }
                return .alternate(nodes: out)
            case let .concat(ns):
                return .concat(nodes: ns.map { analyzeLength($0) })
            case let .repeatNode(n, min, max):
                let inner = analyzeLength(n)
                return .repeatNode(node: inner, min: min, max: Swift.min(max, maxLen))
            }
        }

        func lengthSet(of node: Node) -> Set<Int> {
            switch node {
            case let .backRef(i): return groupLenMap[i] ?? [0]
            case let .capture(_, n): return lengthSet(of: n)
            case let .alternate(ns):
                return ns.reduce(Set<Int>()) { $0.union(lengthSet(of: $1)) }
            case let .concat(ns):
                return ns.reduce(Set([0])) { combineSets($0, lengthSet(of: $1), max: maxLen) }
            case let .repeatNode(n, min, max):
                var out = Set<Int>()
                for k in min...max {
                    var dp = Set([0])
                    for _ in 0..<k { dp = combineSets(dp, lengthSet(of: n), max: maxLen) }
                    out.formUnion(dp)
                }
                return out
            default: return node.lengthSet
            }
        }

        func parseAlt() throws -> Node {
            var nodes = [try parseConcat()]
            while !eof && peek() == "|" { _ = next(); nodes.append(try parseConcat()) }
            return nodes.count == 1 ? nodes[0] : .alternate(nodes: nodes)
        }

        func parseConcat() throws -> Node {
            var nodes: [Node] = []
            while !eof && peek() != ")" && peek() != "|" { nodes.append(try parseRepeat()) }
            if nodes.isEmpty { return .concat(nodes: []) }
            return nodes.count == 1 ? nodes[0] : .concat(nodes: nodes)
        }

        func parseRepeat() throws -> Node {
            let node = try parseAtom()
            guard !eof, ["*", "+", "?", "{"].contains(peek()) else { return node }
            let ch = next()
            var min = 0, max = maxLen
            if ch == "*" { min = 0 }
            else if ch == "+" { min = 1 }
            else if ch == "?" { min = 0; max = 1 }
            else {
                min = try readNumber()
                if !eof && peek() == "," {
                    _ = next()
                    max = (!eof && peek() == "}") ? maxLen : try readNumber()
                } else { max = min }
                guard !eof, next() == "}" else { throw RegexError.syntax("Expected }") }
            }
            return .repeatNode(node: node, min: min, max: max)
        }

        func parseAtom() throws -> Node {
            guard !eof else { throw RegexError.syntax("Unexpected EOF") }
            let ch = next()
            switch ch {
            case ".": return .domain(mask: RegexCore.fullMask)
            case "^": return .anchorStart
            case "$": return .anchorEnd
            case "(":
                let idx = groupIndex; groupIndex += 1
                let node = try parseAlt()
                guard !eof, next() == ")" else { throw RegexError.syntax("Expected )") }
                return .capture(index: idx, node: node)
            case "[":
                return try parseCharClass()
            case "\\":
                guard !eof else { throw RegexError.syntax("Bad escape") }
                let esc = next()
                if esc.isNumber {
                    let n = Int(String(esc))!
                    guard n > 0, n < groupIndex else { throw RegexError.syntax("Invalid backref") }
                    return .backRef(index: n)
                }
                return .domain(mask: RegexCore.maskFromChars([esc]))
            default:
                return .domain(mask: RegexCore.maskFromChars([ch]))
            }
        }

        func parseCharClass() throws -> Node {
            var chars = Set<Character>()
            var prev: Character? = nil
            while !eof && peek() != "]" {
                var ch = next()
                var escaped = false
                if ch == "\\", !eof { ch = next(); escaped = true }
                if ch == "-", let p = prev, !escaped, !eof && peek() != "]" {
                    let endCh = next()
                    let loV = min(p.unicodeScalars.first!.value, endCh.unicodeScalars.first!.value)
                    let hiV = max(p.unicodeScalars.first!.value, endCh.unicodeScalars.first!.value)
                    for v in loV...hiV { if let s = UnicodeScalar(v) { chars.insert(Character(s)) } }
                    prev = nil
                    continue
                }
                chars.insert(ch); prev = ch
            }
            guard !eof, next() == "]" else { throw RegexError.syntax("Unclosed char class") }
            return .domain(mask: RegexCore.maskFromChars(Array(chars)))
        }

        func readNumber() throws -> Int {
            var s = ""
            while !eof && peek().isNumber { s.append(next()) }
            guard let v = Int(s) else { throw RegexError.syntax("Expected number") }
            return v
        }

        func peek() -> Character { pattern[pos] }
        @discardableResult func next() -> Character { let c = pattern[pos]; pos += 1; return c }
        var eof: Bool { pos >= pattern.count }
        func void(_: Any) {}
    }

    enum RegexError: Error { case syntax(String) }

    // MARK: - Enumeration

    static func combineSets(_ a: Set<Int>, _ b: Set<Int>, max: Int) -> Set<Int> {
        var out = Set<Int>()
        for x in a { for y in b { if x + y <= max { out.insert(x + y) } } }
        return out
    }

    static func partitions(_ sets: [Set<Int>], target: Int) -> [[Int]] {
        func helper(_ idx: Int, _ rem: Int) -> [[Int]] {
            if idx == sets.count { return rem == 0 ? [[]] : [] }
            var out: [[Int]] = []
            for len in sets[idx].sorted() where len <= rem {
                for tail in helper(idx + 1, rem - len) { out.append([len] + tail) }
            }
            return out
        }
        return helper(0, target)
    }

    static func lengthSet(_ n: Node, groupLens: [Int: Set<Int>], cap: Int) -> Set<Int> {
        switch n {
        case .domain: return [1]
        case .anchorStart, .anchorEnd: return [0]
        case let .backRef(i): return groupLens[i] ?? [0]
        case let .capture(_, inner): return lengthSet(inner, groupLens: groupLens, cap: cap)
        case let .alternate(ns):
            return ns.reduce(Set<Int>()) { $0.union(lengthSet($1, groupLens: groupLens, cap: cap)) }
        case let .concat(ns):
            return ns.reduce(Set([0])) { combineSets($0, lengthSet($1, groupLens: groupLens, cap: cap), max: cap) }
        case let .repeatNode(inner, min, max):
            var out = Set<Int>()
            for k in min...max {
                var dp = Set([0])
                for _ in 0..<k { dp = combineSets(dp, lengthSet(inner, groupLens: groupLens, cap: cap), max: cap) }
                out.formUnion(dp)
            }
            return out
        }
    }

    static func enumerate(_ node: Node, targetLen: Int, groupLens: [Int: Set<Int>]) -> [[Instruction]] {
        func lenSet(_ n: Node) -> Set<Int> { lengthSet(n, groupLens: groupLens, cap: targetLen) }
        guard lenSet(node).contains(targetLen) else { return [] }
        switch node {
        case let .domain(mask):
            return targetLen == 1 ? [[Instruction(op: .domain, mask: mask)]] : []
        case .anchorStart, .anchorEnd:
            return targetLen == 0 ? [[]] : []
        case let .backRef(i):
            return [[Instruction(op: .backref, index: i, len: targetLen)]]
        case let .capture(i, n):
            return enumerate(n, targetLen: targetLen, groupLens: groupLens).map {
                [Instruction(op: .captureStart, index: i)] + $0 + [Instruction(op: .captureEnd, index: i)]
            }
        case let .alternate(ns):
            return ns.filter { lenSet($0).contains(targetLen) }
                .flatMap { enumerate($0, targetLen: targetLen, groupLens: groupLens) }
        case let .concat(ns):
            let sets = ns.map { lenSet($0) }
            return partitions(sets, target: targetLen).flatMap { split in
                combineSequences(ns, split: split, groupLens: groupLens)
            }
        case let .repeatNode(n, min, max):
            var out: [[Instruction]] = []
            for k in min...max {
                let reps = Array(repeating: n, count: k)
                let sets = reps.map { lenSet($0) }
                for split in partitions(sets, target: targetLen) {
                    out += combineSequences(reps, split: split, groupLens: groupLens)
                }
            }
            return out
        }
    }

    static func combineSequences(_ nodes: [Node], split: [Int], groupLens: [Int: Set<Int>]) -> [[Instruction]] {
        var acc: [[Instruction]] = [[]]
        for (node, len) in zip(nodes, split) {
            let parts = enumerate(node, targetLen: len, groupLens: groupLens)
            guard !parts.isEmpty else { return [] }
            acc = acc.flatMap { a in parts.map { a + $0 } }
        }
        return acc
    }

    static func evaluate(_ seq: [Instruction], targetLen: Int) -> Evaluation? {
        var domains = Array(repeating: fullMask, count: targetLen)
        var starts: [Int: Int] = [:]
        var captures: [Int: [Int]] = [:]
        var eqs: [(Int, Int)] = []
        var pos = 0
        for ins in seq {
            switch ins.op {
            case .domain:
                guard pos < targetLen else { return nil }
                domains[pos] &= ins.mask
                guard domains[pos] != 0 else { return nil }
                pos += 1
            case .captureStart: starts[ins.index] = pos
            case .captureEnd:
                guard let s = starts[ins.index] else { return nil }
                captures[ins.index] = Array(s..<pos)
            case .backref:
                guard let span = captures[ins.index], span.count == ins.len,
                      pos + ins.len <= targetLen else { return nil }
                for i in 0..<ins.len {
                    let a = pos + i, b = span[i]
                    if a != b { eqs.append(a < b ? (a, b) : (b, a)) }
                }
                pos += ins.len
            }
        }
        guard pos == targetLen else { return nil }
        return Evaluation(domains: domains, equalities: eqs)
    }

    // MARK: - Public entry points

    static func validEvaluations(pattern: String, targetLen: Int) throws -> [Evaluation] {
        let parser = Parser(pattern: pattern, maxLen: targetLen)
        let ast = try parser.parse()
        // 解析中に収集したグループ長を使う(後方参照の解決に必要)
        let groupLens = parser.groupLenMap
        guard lengthSet(ast, groupLens: groupLens, cap: targetLen).contains(targetLen) else { return [] }
        var out: [Evaluation] = []
        for seq in enumerate(ast, targetLen: targetLen, groupLens: groupLens) {
            if let e = evaluate(seq, targetLen: targetLen) { out.append(e) }
        }
        return out
    }

    /// マッチするハッシュ総数。JS: countMatchingHashes
    static func countMatchingHashes(_ pattern: String, targetLen: Int) throws -> UInt64 {
        // 総数は 64^12 を超え得るため Double で近似せず UInt64 飽和で返す
        var total = UInt64(0)
        for ev in try validEvaluations(pattern: pattern, targetLen: targetLen) {
            let uf = UnionFind(targetLen)
            for (a, b) in ev.equalities { uf.union(a, b) }
            var compMask: [Int: UInt64] = [:]
            for i in 0..<targetLen {
                let r = uf.find(i)
                compMask[r] = (compMask[r] ?? fullMask) & ev.domains[i]
            }
            var count: UInt64 = 1
            for m in compMask.values {
                let s = popcount(m)
                guard s > 0 else { count = 0; break }
                count = count &* s
            }
            total = total &+ count
        }
        return total
    }

    /// コンパイル結果。JS: compileRegexToLogic の cases 相当
    struct CompiledCase: Hashable {
        var domains: [UInt64]
        var equalities: [(Int, Int)]

        func hash(into hasher: inout Hasher) {
            hasher.combine(domains)
            for (a, b) in equalities { hasher.combine(a); hasher.combine(b) }
        }
        static func == (lhs: CompiledCase, rhs: CompiledCase) -> Bool {
            lhs.domains == rhs.domains && lhs.equalities.elementsEqual(rhs.equalities, by: { $0 == $1 })
        }
    }

    static func compile(pattern: String, targetLen: Int) throws -> [CompiledCase] {
        var seen = Set<CompiledCase>()
        var out: [CompiledCase] = []
        for ev in try validEvaluations(pattern: pattern, targetLen: targetLen) {
            let norm = Array(Set(ev.equalities.map { "\($0.0):\($0.1)" }))
                .map { s -> (Int, Int) in
                    let p = s.split(separator: ":").map { Int($0)! }
                    return (p[0], p[1])
                }.sorted { $0.0 != $1.0 ? $0.0 < $1.0 : $0.1 < $1.1 }
            let c = CompiledCase(domains: ev.domains, equalities: norm)
            if seen.insert(c).inserted { out.append(c) }
        }
        return out
    }

    // MARK: - UnionFind

    final class UnionFind {
        var parent: [Int]
        init(_ n: Int) { parent = Array(0..<n) }
        func find(_ x: Int) -> Int {
            if parent[x] != x { parent[x] = find(parent[x]) }
            return parent[x]
        }
        func union(_ a: Int, _ b: Int) {
            let ra = find(a), rb = find(b)
            if ra != rb { parent[rb] = ra }
        }
    }
}
