package assess

import (
	"strconv"
	"strings"
)

// compareNuGet 按 NuGet 版本规则比较。
// compareNuGet compares versions with the NuGet version rules.
//
// 主次版本、补丁和可选修订号按整数比较，缺省补 0，因此 1、1.0.0 和 1.0.0.0 相等。预发布标识不区分大小写，并且小于同一数字版本。构建元数据不参与先后。超过四段数字或标识非法时返回 false。
// Major, minor, patch, and the optional revision compare as integers. Missing components are 0, so 1, 1.0.0, and 1.0.0.0 are equal. Prerelease identifiers are case-insensitive and sort before the same numeric version. Build metadata does not affect precedence. It returns false when there are more than four numeric components or an identifier is invalid.
func compareNuGet(left, right string) (int, bool) {
	a, aok := parseNuGet(left)
	b, bok := parseNuGet(right)
	if !aok || !bok {
		return 0, false
	}
	for i := 0; i < 4; i++ {
		if a.numbers[i] != b.numbers[i] {
			return cmpInt(a.numbers[i], b.numbers[i]), true
		}
	}
	if len(a.pre) == 0 && len(b.pre) == 0 {
		return 0, true
	}
	if len(a.pre) == 0 {
		return 1, true
	}
	if len(b.pre) == 0 {
		return -1, true
	}
	n := len(a.pre)
	if len(b.pre) < n {
		n = len(b.pre)
	}
	for i := 0; i < n; i++ {
		if cmp := compareSemIdent(a.pre[i], b.pre[i]); cmp != 0 {
			return cmp, true
		}
	}
	return cmpInt(len(a.pre), len(b.pre)), true
}

func normalizeNuGet(raw string) (string, bool) {
	parsed, ok := parseNuGet(raw)
	if !ok {
		return "", false
	}
	out := strconv.Itoa(parsed.numbers[0]) + "." + strconv.Itoa(parsed.numbers[1]) + "." + strconv.Itoa(parsed.numbers[2])
	if parsed.numbers[3] != 0 {
		out += "." + strconv.Itoa(parsed.numbers[3])
	}
	if len(parsed.pre) > 0 {
		parts := make([]string, len(parsed.pre))
		for i, item := range parsed.pre {
			if item.numeric {
				parts[i] = strconv.Itoa(item.number)
				continue
			}
			parts[i] = item.text
		}
		out += "-" + strings.Join(parts, ".")
	}
	return out, true
}

type nugetVersion struct {
	numbers [4]int
	pre     []semIdent
}

func parseNuGet(raw string) (nugetVersion, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, " \t") {
		return nugetVersion{}, false
	}
	if plus := strings.IndexByte(raw, '+'); plus >= 0 {
		if !validSemBuild(raw[plus+1:]) {
			return nugetVersion{}, false
		}
		raw = raw[:plus]
	}
	pre := ""
	if dash := strings.IndexByte(raw, '-'); dash >= 0 {
		pre = raw[dash+1:]
		raw = raw[:dash]
		if pre == "" {
			return nugetVersion{}, false
		}
	}
	numbers := strings.Split(raw, ".")
	if len(numbers) == 0 || len(numbers) > 4 {
		return nugetVersion{}, false
	}
	parsed := nugetVersion{}
	for i, part := range numbers {
		number, ok := semNumber(part, true)
		if !ok {
			return nugetVersion{}, false
		}
		parsed.numbers[i] = number
	}
	if pre != "" {
		for _, part := range strings.Split(pre, ".") {
			item, ok := parseNuGetIdent(part)
			if !ok {
				return nugetVersion{}, false
			}
			parsed.pre = append(parsed.pre, item)
		}
	}
	return parsed, true
}

func parseNuGetIdent(part string) (semIdent, bool) {
	if part == "" {
		return semIdent{}, false
	}
	numeric := true
	for _, r := range part {
		if r < '0' || r > '9' {
			numeric = false
			break
		}
	}
	if numeric {
		number, ok := semNumber(part, true)
		if !ok {
			return semIdent{}, false
		}
		return semIdent{numeric: true, number: number}, true
	}
	for _, r := range part {
		if (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || r == '-' {
			continue
		}
		return semIdent{}, false
	}
	return semIdent{text: strings.ToLower(part)}, true
}
