package assess

import (
	"strconv"
	"strings"
)

// SemVer 2.0.0 的比较不看构建元数据。semver 与 npm 使用同一套先后规则。
// SemVer 2.0.0 precedence ignores build metadata. The semver and npm ecosystems share that precedence.

type semVersion struct {
	major int
	minor int
	patch int
	pre   []semIdent
	build string
}

type semIdent struct {
	numeric bool
	number  int
	text    string
}

func normalizeSemver(raw string) (string, bool) {
	parsed, ok := parseSemver(raw)
	if !ok {
		return "", false
	}
	return parsed.canonical(), true
}

func compareSemver(left, right string) (int, bool) {
	a, aok := parseSemver(left)
	b, bok := parseSemver(right)
	if !aok || !bok {
		return 0, false
	}
	return a.cmp(b), true
}

func parseSemver(raw string) (semVersion, bool) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "v") || strings.HasPrefix(raw, "V") {
		raw = raw[1:]
	}
	if raw == "" || strings.ContainsAny(raw, " \t") {
		return semVersion{}, false
	}
	build := ""
	if plus := strings.IndexByte(raw, '+'); plus >= 0 {
		build = raw[plus+1:]
		raw = raw[:plus]
		if !validSemBuild(build) {
			return semVersion{}, false
		}
	}
	pre := ""
	if dash := strings.IndexByte(raw, '-'); dash >= 0 {
		pre = raw[dash+1:]
		raw = raw[:dash]
		if pre == "" {
			return semVersion{}, false
		}
	}
	numbers := strings.Split(raw, ".")
	if len(numbers) != 3 {
		return semVersion{}, false
	}
	parsed := semVersion{build: build}
	values := []*int{&parsed.major, &parsed.minor, &parsed.patch}
	for i, part := range numbers {
		number, ok := semNumber(part, false)
		if !ok {
			return semVersion{}, false
		}
		*values[i] = number
	}
	if pre != "" {
		for _, part := range strings.Split(pre, ".") {
			item, ok := parseSemIdent(part)
			if !ok {
				return semVersion{}, false
			}
			parsed.pre = append(parsed.pre, item)
		}
	}
	return parsed, true
}

func parseSemIdent(part string) (semIdent, bool) {
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
		number, ok := semNumber(part, false)
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
	return semIdent{text: part}, true
}

func semNumber(part string, allowLeadingZero bool) (int, bool) {
	if part == "" {
		return 0, false
	}
	if len(part) > 1 && part[0] == '0' && !allowLeadingZero {
		return 0, false
	}
	for _, r := range part {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	number, err := strconv.Atoi(part)
	if err != nil {
		return 0, false
	}
	return number, true
}

func validSemBuild(value string) bool {
	if value == "" {
		return false
	}
	for _, part := range strings.Split(value, ".") {
		if part == "" {
			return false
		}
		for _, r := range part {
			if (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func (v semVersion) canonical() string {
	out := strconv.Itoa(v.major) + "." + strconv.Itoa(v.minor) + "." + strconv.Itoa(v.patch)
	if len(v.pre) > 0 {
		parts := make([]string, len(v.pre))
		for i, item := range v.pre {
			if item.numeric {
				parts[i] = strconv.Itoa(item.number)
			} else {
				parts[i] = item.text
			}
		}
		out += "-" + strings.Join(parts, ".")
	}
	if v.build != "" {
		out += "+" + v.build
	}
	return out
}

func (v semVersion) cmp(other semVersion) int {
	if v.major != other.major {
		return cmpInt(v.major, other.major)
	}
	if v.minor != other.minor {
		return cmpInt(v.minor, other.minor)
	}
	if v.patch != other.patch {
		return cmpInt(v.patch, other.patch)
	}
	if len(v.pre) == 0 && len(other.pre) == 0 {
		return 0
	}
	if len(v.pre) == 0 {
		return 1
	}
	if len(other.pre) == 0 {
		return -1
	}
	n := len(v.pre)
	if len(other.pre) < n {
		n = len(other.pre)
	}
	for i := 0; i < n; i++ {
		if cmp := compareSemIdent(v.pre[i], other.pre[i]); cmp != 0 {
			return cmp
		}
	}
	return cmpInt(len(v.pre), len(other.pre))
}

func compareSemIdent(left, right semIdent) int {
	if left.numeric != right.numeric {
		if left.numeric {
			return -1
		}
		return 1
	}
	if left.numeric {
		return cmpInt(left.number, right.number)
	}
	if left.text < right.text {
		return -1
	}
	if left.text > right.text {
		return 1
	}
	return 0
}

func cmpInt(left, right int) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}
