package assess

import "strings"

// compareAlpine 按当前 apk-tools 的分段规则比较两个 Alpine 包版本。
// compareAlpine compares two Alpine package versions with the current apk-tools segment rules.
//
// 首段必须是数字。alpha、beta、pre 和 rc 小于发行版本。额外的数字段、-rN、cvs、svn、git、hg 和 p 大于发行版本。字母段也大于被它延长的版本。点号后的前导零按文本比较。非法版本返回 false。
// The first segment must be numeric. alpha, beta, pre, and rc sort before the release. An extra numeric segment, -rN, cvs, svn, git, hg, and p sort after the release. A letter segment also sorts after the version it extends. A leading zero after a dot compares as text. An invalid version returns false.
const (
	apkInitial = iota
	apkNumber
	apkLetterToken
	apkSuffixToken
	apkSuffixNumber
	apkCommit
	apkRevision
	apkFinished
	apkRejected
)

const (
	apkSuffixInvalid = iota
	apkSuffixAlpha
	apkSuffixBeta
	apkSuffixPre
	apkSuffixRC
	apkSuffixNone
	apkSuffixCVS
	apkSuffixSVN
	apkSuffixGit
	apkSuffixHG
	apkSuffixP
)

func compareAlpine(left, right string) (int, bool) {
	a, aok := parseAlpine(left)
	b, bok := parseAlpine(right)
	if !aok || !bok {
		return 0, false
	}
	i := 0
	for i < len(a) && i < len(b) && a[i].kind == b[i].kind {
		if cmp := compareAlpineToken(a[i], b[i]); cmp != 0 {
			return cmp, true
		}
		i++
	}
	leftKind, rightKind := apkFinished, apkFinished
	var leftSuffix, rightSuffix int
	if i < len(a) {
		leftKind = a[i].kind
		leftSuffix = a[i].suffix
	}
	if i < len(b) {
		rightKind = b[i].kind
		rightSuffix = b[i].suffix
	}
	if leftKind == rightKind {
		return 0, true
	}
	if leftKind == apkSuffixToken && leftSuffix < apkSuffixNone {
		return -1, true
	}
	if rightKind == apkSuffixToken && rightSuffix < apkSuffixNone {
		return 1, true
	}
	if leftKind > rightKind {
		return -1, true
	}
	return 1, true
}

func normalizeAlpine(raw string) (string, bool) {
	if _, ok := parseAlpine(raw); !ok {
		return "", false
	}
	return raw, true
}

type alpineToken struct {
	kind   int
	number uint64
	text   string
	suffix int
}

func parseAlpine(raw string) ([]alpineToken, bool) {
	if raw == "" || raw[0] < '0' || raw[0] > '9' {
		return nil, false
	}
	number, text, next, ok := alpineDigits(raw, 0)
	if !ok {
		return nil, false
	}
	tokens := []alpineToken{{kind: apkInitial, number: number, text: text}}
	kind := apkInitial
	for next < len(raw) {
		switch raw[next] {
		case 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z':
			if kind > apkNumber {
				return nil, false
			}
			tokens = append(tokens, alpineToken{kind: apkLetterToken, text: raw[next : next+1]})
			kind = apkLetterToken
			next++
		case '.':
			if kind > apkNumber {
				return nil, false
			}
			next++
			number, text, next, ok = alpineDigits(raw, next)
			if !ok {
				return nil, false
			}
			tokens = append(tokens, alpineToken{kind: apkNumber, number: number, text: text})
			kind = apkNumber
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			switch kind {
			case apkInitial, apkNumber:
				kind = apkNumber
			case apkSuffixToken:
				kind = apkSuffixNumber
			default:
				return nil, false
			}
			number, text, next, ok = alpineDigits(raw, next)
			if !ok {
				return nil, false
			}
			tokens = append(tokens, alpineToken{kind: kind, number: number, text: text})
		case '_':
			if kind > apkSuffixNumber {
				return nil, false
			}
			next++
			start := next
			for next < len(raw) && raw[next] >= 'a' && raw[next] <= 'z' {
				next++
			}
			suffix, good := alpineSuffix(raw[start:next])
			if !good {
				return nil, false
			}
			tokens = append(tokens, alpineToken{kind: apkSuffixToken, suffix: suffix, text: raw[start:next]})
			kind = apkSuffixToken
		case '~':
			if kind >= apkCommit {
				return nil, false
			}
			next++
			start := next
			for next < len(raw) && isHex(raw[next]) {
				next++
			}
			if start == next {
				return nil, false
			}
			tokens = append(tokens, alpineToken{kind: apkCommit, text: raw[start:next]})
			kind = apkCommit
		case '-':
			if kind >= apkRevision || !strings.HasPrefix(raw[next:], "-r") {
				return nil, false
			}
			next += 2
			number, text, next, ok = alpineDigits(raw, next)
			if !ok {
				return nil, false
			}
			tokens = append(tokens, alpineToken{kind: apkRevision, number: number, text: text})
			kind = apkRevision
		default:
			return nil, false
		}
	}
	return tokens, true
}

func compareAlpineToken(left, right alpineToken) int {
	switch left.kind {
	case apkNumber:
		if strings.HasPrefix(left.text, "0") || strings.HasPrefix(right.text, "0") {
			return compareAlpineText(left.text, right.text)
		}
		return compareAlpineNumber(left.number, right.number)
	case apkInitial, apkSuffixNumber, apkRevision:
		return compareAlpineNumber(left.number, right.number)
	case apkLetterToken, apkCommit:
		return compareAlpineText(left.text, right.text)
	case apkSuffixToken:
		return compareAlpineNumber(uint64(left.suffix), uint64(right.suffix))
	default:
		return compareAlpineText(left.text, right.text)
	}
}

func compareAlpineNumber(left, right uint64) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func compareAlpineText(left, right string) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func alpineDigits(raw string, index int) (uint64, string, int, bool) {
	start := index
	var number uint64
	for index < len(raw) && raw[index] >= '0' && raw[index] <= '9' {
		next := number*10 + uint64(raw[index]-'0')
		if next < number {
			return 0, "", 0, false
		}
		number = next
		index++
	}
	if index == start {
		return 0, "", 0, false
	}
	return number, raw[start:index], index, true
}

func alpineSuffix(name string) (int, bool) {
	switch name {
	case "alpha":
		return apkSuffixAlpha, true
	case "beta":
		return apkSuffixBeta, true
	case "pre":
		return apkSuffixPre, true
	case "rc":
		return apkSuffixRC, true
	case "cvs":
		return apkSuffixCVS, true
	case "svn":
		return apkSuffixSVN, true
	case "git":
		return apkSuffixGit, true
	case "hg":
		return apkSuffixHG, true
	case "p":
		return apkSuffixP, true
	default:
		return apkSuffixInvalid, false
	}
}

func isHex(value byte) bool {
	return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') || (value >= 'A' && value <= 'F')
}
