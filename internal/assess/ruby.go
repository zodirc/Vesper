package assess

import (
	"strconv"
	"strings"
)

// compareRuby 按 RubyGems 的分段规则比较版本。
// compareRuby compares versions with the RubyGems segment rules.
//
// 缺少的数值段按 0 补齐，因此 1、1.0 和 1.0.0 相等。字母段小于同一位置的数字。连字符按 .pre. 解释。无法分段时返回 false。
// A missing numeric segment is padded with 0, so 1, 1.0, and 1.0.0 are equal. A letter segment is less than a number in the same position. A hyphen is read as .pre. It returns false when the version cannot be segmented.
func compareRuby(left, right string) (int, bool) {
	a, aok := parseRuby(left)
	b, bok := parseRuby(right)
	if !aok || !bok {
		return 0, false
	}
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		leftSeg, rightSeg := rubyPad(a, i), rubyPad(b, i)
		if leftSeg.numeric != rightSeg.numeric {
			if leftSeg.numeric {
				return 1, true
			}
			return -1, true
		}
		if leftSeg.numeric {
			if leftSeg.number != rightSeg.number {
				return cmpInt(leftSeg.number, rightSeg.number), true
			}
			continue
		}
		if leftSeg.text != rightSeg.text {
			if leftSeg.text < rightSeg.text {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

func normalizeRuby(raw string) (string, bool) {
	parts, ok := parseRuby(raw)
	if !ok {
		return "", false
	}
	for len(parts) > 1 && parts[len(parts)-1].numeric && parts[len(parts)-1].number == 0 {
		parts = parts[:len(parts)-1]
	}
	out := make([]string, len(parts))
	for i, part := range parts {
		if part.numeric {
			out[i] = strconv.Itoa(part.number)
			continue
		}
		out[i] = part.text
	}
	return strings.Join(out, "."), true
}

type rubySegment struct {
	numeric bool
	number  int
	text    string
}

func rubyPad(parts []rubySegment, index int) rubySegment {
	if index >= len(parts) {
		return rubySegment{numeric: true}
	}
	return parts[index]
}

func parseRuby(raw string) ([]rubySegment, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, " \t") {
		return nil, false
	}
	raw = strings.ReplaceAll(raw, "-", ".pre.")
	var out []rubySegment
	for _, part := range strings.Split(raw, ".") {
		if part == "" {
			return nil, false
		}
		for i := 0; i < len(part); {
			if part[i] >= '0' && part[i] <= '9' {
				j := i + 1
				for j < len(part) && part[j] >= '0' && part[j] <= '9' {
					j++
				}
				number, err := strconv.Atoi(strings.TrimLeft(part[i:j], "0"))
				if err != nil {
					if strings.TrimLeft(part[i:j], "0") != "" {
						return nil, false
					}
					number = 0
				}
				out = append(out, rubySegment{numeric: true, number: number})
				i = j
				continue
			}
			if isAlpha(part[i]) {
				j := i + 1
				for j < len(part) && isAlpha(part[j]) {
					j++
				}
				out = append(out, rubySegment{text: part[i:j]})
				i = j
				continue
			}
			return nil, false
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}
