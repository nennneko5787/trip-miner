import Foundation

/// Web版 logic-optimizer.js の Swift 移植。
/// RegexCore.CompiledCase 群 → 論理AST → 正規化・因数分解。
enum LogicOptimizer {
    indirect enum Node: Hashable {
        case t, f
        case lit(charIndex: Int, mask: UInt64) // char[i] ∈ mask
        case eq(a: Int, b: Int) // char[a] == char[b] (a < b に正規化)
        case and([Node])
        case or([Node])
    }

    /// cases → OR(AND(…)) の AST を組み立てる
    static func build(cases: [RegexCore.CompiledCase]) -> Node {
        let caseNodes: [Node] = cases.map { c in
            var parts: [Node] = []
            for (i, m) in c.domains.enumerated() where m != RegexCore.fullMask {
                parts.append(.lit(charIndex: i, mask: m))
            }
            for (a, b) in c.equalities {
                parts.append(.eq(a: min(a, b), b: max(a, b)))
            }
            if parts.isEmpty { return .t }
            if parts.count == 1 { return parts[0] }
            return .and(parts)
        }
        if caseNodes.isEmpty { return .f }
        if caseNodes.count == 1 { return caseNodes[0] }
        return .or(caseNodes)
    }

    static func key(_ n: Node) -> String {
        switch n {
        case .t: return "T"
        case .f: return "F"
        case let .lit(i, m): return "c[\(i)]&\(String(m, radix: 16))"
        case let .eq(a, b): return "c[\(a)]==c[\(b)]"
        case let .and(ns): return "(" + ns.map(key).sorted().joined(separator: "&") + ")"
        case let .or(ns): return "(" + ns.map(key).sorted().joined(separator: "|") + ")"
        }
    }

    /// 平坦化・定数畳み込み・重複排除・吸収則
    static func normalize(_ node: Node) -> Node {
        switch node {
        case .t, .f, .lit, .eq: return node
        case let .and(ns), let .or(ns):
            let isAnd: Bool
            if case .and = node { isAnd = true } else { isAnd = false }
            // 平坦化
            var flat: [Node] = []
            for c in ns {
                let n = normalize(c)
                if case let .and(inner) = n, isAnd { flat += inner }
                else if case let .or(inner) = n, !isAnd { flat += inner }
                else { flat.append(n) }
            }
            // 定数畳み込み
            let absorb: Node = isAnd ? .f : .t
            let ident: Node = isAnd ? .t : .f
            if flat.contains(absorb) { return absorb }
            flat = flat.filter { $0 != ident }
            // 重複排除
            var uniq: [String: Node] = [:]
            for n in flat { uniq[key(n)] = n }
            var nodes = uniq.values.sorted { key($0) < key($1) }
            // 吸収則 A | (A & B) -> A
            let keys = Set(uniq.keys)
            let sub: (Node) -> [Node]? = { n in
                if isAnd, case let .or(inner) = n { return inner }
                if !isAnd, case let .and(inner) = n { return inner }
                return nil
            }
            nodes = nodes.filter { n in
                guard let members = sub(n) else { return true }
                return !members.contains { keys.contains(key($0)) }
            }
            // 同一文字位置のリテラル統合 (c[i]∈m1 | c[i]∈m2 → c[i]∈m1|m2)
            if !isAnd {
                var merged: [Int: UInt64] = [:]
                var rest: [Node] = []
                for n in nodes {
                    if case let .lit(i, m) = n { merged[i] = (merged[i] ?? 0) | m }
                    else { rest.append(n) }
                }
                nodes = rest + merged.map { .lit(charIndex: $0.key, mask: $0.value) }
            }
            if nodes.isEmpty { return ident }
            if nodes.count == 1 { return nodes[0] }
            return isAnd ? .and(nodes) : .or(nodes)
        }
    }

    /// 共通因数の括り出しを1回試み、再帰的に適用
    static func factor(_ node: Node) -> Node {
        let curr = normalize(node)
        switch curr {
        case let .and(ns), let .or(ns):
            let isOr: Bool
            if case .or = curr { isOr = true } else { isOr = false }
            let factored = ns.map(factor)
            // メンバ展開
            func members(_ n: Node) -> [Node] {
                if isOr, case let .and(inner) = n { return inner }
                if !isOr, case let .or(inner) = n { return inner }
                return [n]
            }
            var freq: [String: Int] = [:]
            var repr: [String: Node] = [:]
            for n in factored {
                for m in Set(members(n).map(key)) {
                    freq[m, default: 0] += 1
                    if repr[m] == nil { repr[m] = members(n).first { key($0) == m } }
                }
            }
            guard let best = freq.filter({ $0.value > 1 }).max(by: { $0.value < $1.value })?.key,
                  let bestNode = repr[best] else { return curr }
            var matched: [Node] = []
            var rest: [Node] = []
            for n in factored {
                let ms = members(n)
                if let idx = ms.firstIndex(where: { key($0) == best }) {
                    var remain = ms
                    remain.remove(at: idx)
                    if remain.isEmpty { matched.append(isOr ? .t : .f) }
                    else if remain.count == 1 { matched.append(remain[0]) }
                    else { matched.append(isOr ? .and(remain) : .or(remain)) }
                } else { rest.append(n) }
            }
            let sub: Node = isOr ? .and(matched) : .or(matched)
            let factoredPart = normalize(isOr ? .and([bestNode, factor(sub)]) : .or([bestNode, factor(sub)]))
            return factor(normalize(isOr ? .or(rest + [factoredPart]) : .and(rest + [factoredPart])))
        default:
            return curr
        }
    }

    static func optimize(cases: [RegexCore.CompiledCase]) -> Node {
        factor(build(cases: cases))
    }
}
