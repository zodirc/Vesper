package assess

import (
	"fmt"
	"strconv"
	"strings"
)

// NormalizeVersion 按产品生态生成可比较的版本文本，不改写调用方持有的原始字符串。
// NormalizeVersion builds comparable version text for a product ecosystem. It does not rewrite the caller's original string.
//
// generic 去掉数字分量的前导零。deb 写成 epoch:upstream 或 epoch:upstream-revision。rpm 写成 epoch:version 或 epoch:version-release。apk 保留 apk-tools 接受的原文。semver、npm、Go、crates.io、Hex、Pub 和 Swift 按 SemVer 2.0.0 去掉可选的前导 v。pypi 按 PEP 440 写成规范文本。maven 按 ComparableVersion 写成规范文本。rubygems、nuget 和 packagist 写成各自的规范文本。无法按该生态解析，以及其他生态，返回空字符串和 false。
// generic strips leading zeros from numeric components. deb is rendered as epoch:upstream or epoch:upstream-revision. rpm is rendered as epoch:version or epoch:version-release. apk keeps text accepted by apk-tools. semver, npm, Go, crates.io, Hex, Pub, and Swift follow SemVer 2.0.0 and drop an optional leading v. pypi uses the PEP 440 canonical text. maven uses the ComparableVersion canonical text. rubygems, nuget, and packagist use their own canonical text. An empty string and false are returned when the version cannot be parsed for that ecosystem, and for every other ecosystem.
func NormalizeVersion(ecosystem, raw string) (string, bool) {
	if raw == "" {
		return "", false
	}
	switch Scheme(ecosystem) {
	case "generic":
		return normalizeGeneric(raw)
	case "deb":
		return normalizeDeb(raw)
	case "rpm":
		return normalizeRPM(raw)
	case "apk":
		return normalizeAlpine(raw)
	case "semver":
		return normalizeSemver(raw)
	case "pypi":
		return normalizePyPI(raw)
	case "maven":
		return normalizeMaven(raw)
	case "rubygems":
		return normalizeRuby(raw)
	case "nuget":
		return normalizeNuGet(raw)
	case "composer":
		return normalizeComposer(raw)
	default:
		return "", false
	}
}

func normalizeGeneric(raw string) (string, bool) {
	parts := strings.Split(raw, ".")
	out := make([]string, len(parts))
	for i := range parts {
		value, ok := component(parts, i)
		if !ok {
			return "", false
		}
		out[i] = strconv.Itoa(value)
	}
	return strings.Join(out, "."), true
}

func normalizeDeb(raw string) (string, bool) {
	epoch, upstream, revision, ok := splitDeb(raw)
	if !ok {
		return "", false
	}
	if revision == "" {
		return fmt.Sprintf("%d:%s", epoch, upstream), true
	}
	return fmt.Sprintf("%d:%s-%s", epoch, upstream, revision), true
}

func normalizeRPM(raw string) (string, bool) {
	epoch, version, release, ok := splitRPM(raw)
	if !ok {
		return "", false
	}
	if release == "" {
		return fmt.Sprintf("%d:%s", epoch, version), true
	}
	return fmt.Sprintf("%d:%s-%s", epoch, version, release), true
}

// compareDeb 按 Debian 策略 5.6.12 比较两个包版本。
// compareDeb compares two package versions using Debian Policy 5.6.12.
//
// 先比较 epoch，再比较 upstream，最后比较 debian revision。版本含非法字符或无法拆分时，第二个返回值为 false。
// Epoch is compared first, then upstream, then the Debian revision. The second result is false when a version contains illegal characters or cannot be split.
func compareDeb(left, right string) (int, bool) {
	le, lu, lr, ok := splitDeb(left)
	if !ok {
		return 0, false
	}
	re, ru, rr, ok := splitDeb(right)
	if !ok {
		return 0, false
	}
	if le != re {
		if le < re {
			return -1, true
		}
		return 1, true
	}
	if cmp := debVerrevcmp(lu, ru); cmp != 0 {
		return cmp, true
	}
	return debVerrevcmp(lr, rr), true
}

// compareRPM 按 RPM EVR 比较两个包版本。
// compareRPM compares two package versions as RPM epoch, version, and release.
//
// epoch 缺省为 0。最后一个连字符分隔 release，第一个冒号分隔 epoch。比较算法与 rpmvercmp 一致，包含 ~ 和 ^。无法解析时第二个返回值为 false。
// A missing epoch is 0. The last hyphen separates the release and the first colon separates the epoch. Comparison follows rpmvercmp, including ~ and ^. The second result is false when the version cannot be parsed.
func compareRPM(left, right string) (int, bool) {
	le, lv, lr, ok := splitRPM(left)
	if !ok {
		return 0, false
	}
	re, rv, rr, ok := splitRPM(right)
	if !ok {
		return 0, false
	}
	if le != re {
		if le < re {
			return -1, true
		}
		return 1, true
	}
	if cmp := rpmvercmp(lv, rv); cmp != 0 {
		return cmp, true
	}
	return rpmvercmp(lr, rr), true
}

func splitDeb(value string) (epoch int, upstream, revision string, ok bool) {
	if !validVersion(value, debChar) {
		return 0, "", "", false
	}
	rest := value
	if colon := strings.IndexByte(value, ':'); colon >= 0 {
		parsed, good := parseEpoch(value[:colon])
		if !good || strings.Contains(value[colon+1:], ":") {
			return 0, "", "", false
		}
		epoch = parsed
		rest = value[colon+1:]
	}
	if hyphen := strings.LastIndexByte(rest, '-'); hyphen >= 0 {
		upstream = rest[:hyphen]
		revision = rest[hyphen+1:]
	} else {
		upstream = rest
	}
	if upstream == "" {
		return 0, "", "", false
	}
	return epoch, upstream, revision, true
}

func splitRPM(value string) (epoch int, version, release string, ok bool) {
	if !validVersion(value, rpmChar) {
		return 0, "", "", false
	}
	rest := value
	if hyphen := strings.LastIndexByte(value, '-'); hyphen >= 0 {
		rest = value[:hyphen]
		release = value[hyphen+1:]
	}
	if colon := strings.IndexByte(rest, ':'); colon >= 0 {
		parsed, good := parseEpoch(rest[:colon])
		if !good || strings.Contains(rest[colon+1:], ":") {
			return 0, "", "", false
		}
		epoch = parsed
		rest = rest[colon+1:]
	}
	if rest == "" {
		return 0, "", "", false
	}
	return epoch, rest, release, true
}

func parseEpoch(value string) (int, bool) {
	if value == "" {
		return 0, false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 31)
	if err != nil {
		return 0, false
	}
	return int(parsed), true
}

func validVersion(value string, allowed func(byte) bool) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if !allowed(value[i]) {
			return false
		}
	}
	return true
}

func debChar(c byte) bool {
	return isAlnum(c) || c == '.' || c == '+' || c == '~' || c == '-' || c == ':'
}

func rpmChar(c byte) bool {
	return isAlnum(c) || c == '.' || c == '_' || c == '+' || c == '~' || c == '^' || c == '-' || c == ':'
}

func debVerrevcmp(a, b string) int {
	ia, ib := 0, 0
	for ia < len(a) || ib < len(b) {
		for (ia < len(a) && !isDigit(a[ia])) || (ib < len(b) && !isDigit(b[ib])) {
			ac, bc := 0, 0
			if ia < len(a) {
				ac = debOrder(a[ia])
			}
			if ib < len(b) {
				bc = debOrder(b[ib])
			}
			if ac != bc {
				if ac < bc {
					return -1
				}
				return 1
			}
			if ia < len(a) {
				ia++
			}
			if ib < len(b) {
				ib++
			}
		}
		for ia < len(a) && a[ia] == '0' {
			ia++
		}
		for ib < len(b) && b[ib] == '0' {
			ib++
		}
		first := 0
		for ia < len(a) && ib < len(b) && isDigit(a[ia]) && isDigit(b[ib]) {
			if first == 0 && a[ia] != b[ib] {
				if a[ia] < b[ib] {
					first = -1
				} else {
					first = 1
				}
			}
			ia++
			ib++
		}
		if ia < len(a) && isDigit(a[ia]) {
			return 1
		}
		if ib < len(b) && isDigit(b[ib]) {
			return -1
		}
		if first != 0 {
			return first
		}
	}
	return 0
}

func debOrder(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return 0
	case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'):
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	one, two := 0, 0
	for one < len(a) || two < len(b) {
		for one < len(a) && !isAlnum(a[one]) && a[one] != '~' && a[one] != '^' {
			one++
		}
		for two < len(b) && !isAlnum(b[two]) && b[two] != '~' && b[two] != '^' {
			two++
		}
		oneTilde := one < len(a) && a[one] == '~'
		twoTilde := two < len(b) && b[two] == '~'
		if oneTilde || twoTilde {
			if !oneTilde {
				return 1
			}
			if !twoTilde {
				return -1
			}
			one++
			two++
			continue
		}
		oneCaret := one < len(a) && a[one] == '^'
		twoCaret := two < len(b) && b[two] == '^'
		if oneCaret || twoCaret {
			if one >= len(a) {
				return -1
			}
			if two >= len(b) {
				return 1
			}
			if !oneCaret {
				return 1
			}
			if !twoCaret {
				return -1
			}
			one++
			two++
			continue
		}
		if one >= len(a) || two >= len(b) {
			break
		}
		startOne, startTwo := one, two
		numeric := isDigit(a[one])
		if numeric {
			for one < len(a) && isDigit(a[one]) {
				one++
			}
			for two < len(b) && isDigit(b[two]) {
				two++
			}
		} else {
			for one < len(a) && isAlpha(a[one]) {
				one++
			}
			for two < len(b) && isAlpha(b[two]) {
				two++
			}
		}
		if startOne == one {
			return -1
		}
		if startTwo == two {
			if numeric {
				return 1
			}
			return -1
		}
		segOne := a[startOne:one]
		segTwo := b[startTwo:two]
		if numeric {
			segOne = strings.TrimLeft(segOne, "0")
			segTwo = strings.TrimLeft(segTwo, "0")
			if len(segOne) != len(segTwo) {
				if len(segOne) > len(segTwo) {
					return 1
				}
				return -1
			}
		}
		if segOne != segTwo {
			if segOne < segTwo {
				return -1
			}
			return 1
		}
	}
	if one >= len(a) && two >= len(b) {
		return 0
	}
	if one >= len(a) {
		if two < len(b) && (b[two] == '~' || b[two] == '^') {
			if b[two] == '~' {
				return 1
			}
			return -1
		}
		return -1
	}
	if a[one] == '~' {
		return -1
	}
	if a[one] == '^' {
		return 1
	}
	return 1
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func isAlpha(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func isAlnum(c byte) bool {
	return isDigit(c) || isAlpha(c)
}
