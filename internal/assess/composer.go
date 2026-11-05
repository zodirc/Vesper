package assess

import (
	"strconv"
	"strings"
)

// compareComposer 按 Composer 的版本规范化比较 Packagist 版本。
// compareComposer compares Packagist versions with Composer version normalization.
//
// 数字段最多四段，缺省补 0。稳定度顺序是 dev、alpha、beta、RC、stable、patch。dev- 分支名不能与数字版本排序。无法规范化时返回 false。
// There are at most four numeric components, and missing components are 0. Stability order is dev, alpha, beta, RC, stable, then patch. A dev- branch name is not ordered against a numeric version. It returns false when the version cannot be normalized.
func compareComposer(left, right string) (int, bool) {
	a, aok := parseComposer(left)
	b, bok := parseComposer(right)
	if !aok || !bok {
		return 0, false
	}
	for i := 0; i < 4; i++ {
		if a.numbers[i] != b.numbers[i] {
			return cmpInt(a.numbers[i], b.numbers[i]), true
		}
	}
	if a.stability != b.stability {
		return cmpInt(a.stability, b.stability), true
	}
	return cmpInt(a.stabilityNumber, b.stabilityNumber), true
}

func normalizeComposer(raw string) (string, bool) {
	parsed, ok := parseComposer(raw)
	if !ok {
		return "", false
	}
	out := strconv.Itoa(parsed.numbers[0]) + "." + strconv.Itoa(parsed.numbers[1]) + "." + strconv.Itoa(parsed.numbers[2])
	if parsed.numbers[3] != 0 {
		out += "." + strconv.Itoa(parsed.numbers[3])
	}
	switch parsed.stability {
	case 0:
		out += "-dev"
	case 1:
		out += "-alpha" + stabilitySuffix(parsed.stabilityNumber)
	case 2:
		out += "-beta" + stabilitySuffix(parsed.stabilityNumber)
	case 3:
		out += "-RC" + stabilitySuffix(parsed.stabilityNumber)
	case 5:
		out += "-patch" + stabilitySuffix(parsed.stabilityNumber)
	}
	return out, true
}

func stabilitySuffix(number int) string {
	if number == 0 {
		return ""
	}
	return strconv.Itoa(number)
}

type composerVersion struct {
	numbers         [4]int
	stability       int
	stabilityNumber int
}

func parseComposer(raw string) (composerVersion, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, " \t") || strings.HasPrefix(strings.ToLower(raw), "dev-") {
		return composerVersion{}, false
	}
	if raw[0] == 'v' || raw[0] == 'V' {
		raw = raw[1:]
	}
	if plus := strings.IndexByte(raw, '+'); plus >= 0 {
		raw = raw[:plus]
	}
	name, number, body, ok := composerStability(raw)
	if !ok {
		return composerVersion{}, false
	}
	numbers := strings.Split(body, ".")
	if len(numbers) == 0 || len(numbers) > 4 || body == "" {
		return composerVersion{}, false
	}
	parsed := composerVersion{stability: composerRank(name), stabilityNumber: number}
	for i, part := range numbers {
		value, good := semNumber(part, true)
		if !good {
			return composerVersion{}, false
		}
		parsed.numbers[i] = value
	}
	return parsed, true
}

func composerStability(raw string) (string, int, string, bool) {
	for _, mark := range []string{"-", ""} {
		if mark == "" && !strings.ContainsAny(raw, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			return "stable", 0, raw, true
		}
		for _, name := range []string{"stable", "patch", "pl", "p", "RC", "rc", "beta", "alpha", "dev", "b", "a"} {
			suffix := mark + name
			index := strings.LastIndex(raw, suffix)
			if index <= 0 || index+len(suffix) > len(raw) {
				continue
			}
			if mark == "" && index > 0 && raw[index-1] >= '0' && raw[index-1] <= '9' {
				// glued form such as 1.0.0alpha1
			} else if mark == "" {
				continue
			}
			rest := raw[index+len(suffix):]
			if rest == "" {
				return name, 0, raw[:index], true
			}
			number, ok := semNumber(rest, true)
			if ok {
				return name, number, raw[:index], true
			}
		}
		if mark == "-" {
			continue
		}
	}
	if strings.ContainsAny(raw, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		return "", 0, "", false
	}
	return "stable", 0, raw, true
}

func composerRank(name string) int {
	switch strings.ToLower(name) {
	case "dev":
		return 0
	case "alpha", "a":
		return 1
	case "beta", "b":
		return 2
	case "rc":
		return 3
	case "patch", "p", "pl":
		return 5
	default:
		return 4
	}
}
