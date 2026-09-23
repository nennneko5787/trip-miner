import Foundation

/// Web版 TripMinerApp.validateTarget / formatRegexStr の移植。
struct SearchSettings: Equatable {
    enum MatchType: String { case prefix, suffix, partial }
    var digit: Int // 10 or 12
    var useRegex: Bool
    var matchType: MatchType
    var target: String
}

enum SearchValidator {
    /// 通常モード→正規表現文字列化。JS: formatRegexStr
    static func formatRegex(_ s: SearchSettings) -> String {
        if !s.useRegex {
            let esc = NSRegularExpression.escapedPattern(for: s.target)
            switch s.matchType {
            case .prefix: return "^\(esc).*$"
            case .suffix: return "^.*\(esc)$"
            case .partial: return "^.*\(esc).*$"
            }
        } else {
            var t = s.target
            if !t.hasPrefix("^") { t = "^" + t }
            if !t.hasSuffix("$") { t += "$" }
            return t
        }
    }

    /// 表示用コンパイル結果。JS: updateRegexDisplay
    static func displayRegex(_ s: SearchSettings) -> String {
        guard !s.target.isEmpty else { return "（ターゲットを入力してください）" }
        return formatRegex(s)
    }

    /// 検証。成功時 nil、失敗時エラーメッセージ。JS: validateTarget
    static func validate(_ s: SearchSettings) -> String? {
        guard !s.target.isEmpty else { return "ターゲットを入力してください。" }
        if !s.useRegex {
            guard s.target.allSatisfy({ "./.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".contains($0) }) else {
                return "正規表現なしモードでは ./a-zA-Z0-9 以外の文字は使用できません。"
            }
            if s.digit == 10, s.matchType == .suffix {
                guard let last = s.target.last, TripSpec.validSuffixLast10.contains(last) else {
                    return "10桁・後方一致モードでは、末尾が .26AEIMQUYcgkosw のいずれかである必要があります。"
                }
            }
        } else {
            let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./[]^${}()\\+*,?|-")
            guard s.target.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
                return "正規表現モードで許可されていない文字が含まれています。"
            }
            do { _ = try NSRegularExpression(pattern: s.target) }
            catch { return "正規表現の構文が不正です。" }
        }
        let final = formatRegex(s)
        do {
            let estimated = try RegexCore.countMatchingHashes(final, targetLen: s.digit)
            if estimated == 0 { return "マッチするトリップが存在しない可能性があります。" }
            // 確率バリデーション (JS と同一の閾値)
            let total = pow(64.0, Double(s.digit))
            let threshold = s.digit == 10 ? pow(64.0, 10.0) / pow(64.0, 6.0) : pow(64.0, 12.0) / pow(64.0, 8.0)
            let rate = max(total / Double(max(estimated, 1)), 1)
            if rate < threshold {
                return "マッチ率が高すぎます。条件を厳しくしてください。推定マッチ率: 1/\(formatUnit(rate))"
            }
        } catch {
            return "正規表現の解析に失敗しました: \(error.localizedDescription)"
        }
        return nil
    }

    static func formatUnit(_ num: Double) -> String {
        if num == 0 { return "0" }
        if num < 1000 { return String(Int(num)) }
        let units = ["K", "M", "G", "T", "P", "E"]
        var value = num, i = -1
        while value >= 1000, i < units.count - 1 { value /= 1000; i += 1 }
        return String(format: "%.2f%@", value, units[i])
    }

    /// 正規表現テンプレート (Web版と同一)
    static let templates: [(name: String, pattern: String)] = [
        ("全数", "[0-9]*"),
        ("飛石", ".?([./].)*[./]?"),
        ("拡飛", ".?(.)(.\\1)*.?"),
        ("二構", "(.)\\1*(.)(\\1|\\2)*"),
        ("回文", "(.)(.)(.)(.)(.)(.?)\\6?\\5\\4\\3\\2\\1"),
        ("山彦", "(.*)\\1"),
        ("双連", "((.)\\2)*"),
        ("八雲", ".?((.)\\2\\2)*.?"),
        ("増加", ".(.)\\1(.)\\2\\2(.)\\3{3}"),
        ("減少", "(.)\\1{3}(.)\\2\\2(.)\\3(.)"),
        ("長短", "[MWm]*|[.il]*"),
        ("飛連", ".*(.).*(\\1.*){7}"),
    ]
}
