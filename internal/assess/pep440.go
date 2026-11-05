package assess

import (
	"regexp"
	"strconv"
	"strings"
)

// PEP 440 是 PyPI 的版本规则。比较键与 packaging.version 一致：开发版早于预发布，正式版早于本地版本，本地版本早于 post。
// PEP 440 is the PyPI version rule. The comparison key matches packaging.version: a development release precedes a pre-release, a final release precedes a local version, and a local version precedes a post release.

var pep440Pattern = regexp.MustCompile(`(?i)^v?(?:([0-9]+)\!)?([0-9]+(?:\.[0-9]+)*)(?:[-_\.]?(alpha|a|beta|b|preview|pre|c|rc)[-_\.]?([0-9]+)?)?(?:(?:-([0-9]+))|(?:[-_\.]?(post|rev|r)[-_\.]?([0-9]+)?))?(?:[-_\.]?(dev)[-_\.]?([0-9]+)?)?(?:\+([a-z0-9]+(?:[-_\.][a-z0-9]+)*))?$`)

type pepVersion struct {
	epoch   int
	release []int
	pre     *pepPre
	post    *int
	dev     *int
	local   []pepLocal
}

type pepPre struct {
	letter int
	number int
}

type pepLocal struct {
	numeric bool
	number  int
	text    string
}

func normalizePyPI(raw string) (string, bool) {
	parsed, ok := parsePEP440(raw)
	if !ok {
		return "", false
	}
	return parsed.canonical(), true
}

func comparePyPI(left, right string) (int, bool) {
	a, aok := parsePEP440(left)
	b, bok := parsePEP440(right)
	if !aok || !bok {
		return 0, false
	}
	return a.cmp(b), true
}

func parsePEP440(raw string) (pepVersion, bool) {
	raw = strings.TrimSpace(raw)
	match := pep440Pattern.FindStringSubmatch(raw)
	if match == nil {
		return pepVersion{}, false
	}
	parsed := pepVersion{}
	if match[1] != "" {
		epoch, ok := decimal(match[1])
		if !ok {
			return pepVersion{}, false
		}
		parsed.epoch = epoch
	}
	for _, part := range strings.Split(match[2], ".") {
		number, ok := decimal(part)
		if !ok {
			return pepVersion{}, false
		}
		parsed.release = append(parsed.release, number)
	}
	if match[3] != "" {
		number := 0
		if match[4] != "" {
			value, ok := decimal(match[4])
			if !ok {
				return pepVersion{}, false
			}
			number = value
		}
		parsed.pre = &pepPre{letter: pepLetter(match[3]), number: number}
	}
	if match[5] != "" || match[6] != "" {
		text := match[5]
		if text == "" {
			text = match[7]
		}
		number := 0
		if text != "" {
			value, ok := decimal(text)
			if !ok {
				return pepVersion{}, false
			}
			number = value
		}
		parsed.post = &number
	}
	if match[8] != "" {
		number := 0
		if match[9] != "" {
			value, ok := decimal(match[9])
			if !ok {
				return pepVersion{}, false
			}
			number = value
		}
		parsed.dev = &number
	}
	if match[10] != "" {
		for _, part := range splitLocal(match[10]) {
			if pepDigits(part) {
				number, ok := decimal(part)
				if !ok {
					return pepVersion{}, false
				}
				parsed.local = append(parsed.local, pepLocal{numeric: true, number: number})
				continue
			}
			parsed.local = append(parsed.local, pepLocal{text: strings.ToLower(part)})
		}
	}
	return parsed, len(parsed.release) > 0
}

func splitLocal(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		return r == '.' || r == '_' || r == '-'
	})
}

func pepDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func pepLetter(value string) int {
	switch strings.ToLower(value) {
	case "a", "alpha":
		return 0
	case "b", "beta":
		return 1
	default:
		return 2
	}
}

func decimal(value string) (int, bool) {
	number, err := strconv.Atoi(value)
	if err != nil {
		return 0, false
	}
	return number, true
}

func (v pepVersion) canonical() string {
	var b strings.Builder
	if v.epoch != 0 {
		b.WriteString(strconv.Itoa(v.epoch))
		b.WriteByte('!')
	}
	release := trimZeros(v.release)
	for i, number := range release {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strconv.Itoa(number))
	}
	if v.pre != nil {
		switch v.pre.letter {
		case 0:
			b.WriteByte('a')
		case 1:
			b.WriteByte('b')
		default:
			b.WriteString("rc")
		}
		b.WriteString(strconv.Itoa(v.pre.number))
	}
	if v.post != nil {
		b.WriteString(".post")
		b.WriteString(strconv.Itoa(*v.post))
	}
	if v.dev != nil {
		b.WriteString(".dev")
		b.WriteString(strconv.Itoa(*v.dev))
	}
	if len(v.local) > 0 {
		b.WriteByte('+')
		for i, item := range v.local {
			if i > 0 {
				b.WriteByte('.')
			}
			if item.numeric {
				b.WriteString(strconv.Itoa(item.number))
			} else {
				b.WriteString(item.text)
			}
		}
	}
	return b.String()
}

func trimZeros(values []int) []int {
	end := len(values)
	for end > 1 && values[end-1] == 0 {
		end--
	}
	return values[:end]
}

func (v pepVersion) cmp(other pepVersion) int {
	if v.epoch != other.epoch {
		return cmpInt(v.epoch, other.epoch)
	}
	if cmp := compareInts(v.release, other.release); cmp != 0 {
		return cmp
	}
	if cmp := compareBound(v.preKey(), other.preKey()); cmp != 0 {
		return cmp
	}
	if cmp := compareBound(v.postKey(), other.postKey()); cmp != 0 {
		return cmp
	}
	if cmp := compareBound(v.devKey(), other.devKey()); cmp != 0 {
		return cmp
	}
	return compareLocal(v.local, other.local)
}

type pepBound struct {
	kind   int
	letter int
	number int
}

func (v pepVersion) preKey() pepBound {
	if v.pre == nil && v.post == nil && v.dev != nil {
		return pepBound{kind: -1}
	}
	if v.pre == nil {
		return pepBound{kind: 1}
	}
	return pepBound{letter: v.pre.letter, number: v.pre.number}
}

func (v pepVersion) postKey() pepBound {
	if v.post == nil {
		return pepBound{kind: -1}
	}
	return pepBound{number: *v.post}
}

func (v pepVersion) devKey() pepBound {
	if v.dev == nil {
		return pepBound{kind: 1}
	}
	return pepBound{number: *v.dev}
}

func compareBound(left, right pepBound) int {
	if left.kind != right.kind {
		return cmpInt(left.kind, right.kind)
	}
	if left.letter != right.letter {
		return cmpInt(left.letter, right.letter)
	}
	return cmpInt(left.number, right.number)
}

func compareInts(left, right []int) int {
	n := len(left)
	if len(right) > n {
		n = len(right)
	}
	for i := 0; i < n; i++ {
		lv, rv := 0, 0
		if i < len(left) {
			lv = left[i]
		}
		if i < len(right) {
			rv = right[i]
		}
		if lv != rv {
			return cmpInt(lv, rv)
		}
	}
	return 0
}

func compareLocal(left, right []pepLocal) int {
	if len(left) == 0 && len(right) == 0 {
		return 0
	}
	if len(left) == 0 {
		return -1
	}
	if len(right) == 0 {
		return 1
	}
	n := len(left)
	if len(right) < n {
		n = len(right)
	}
	for i := 0; i < n; i++ {
		if cmp := compareLocalPart(left[i], right[i]); cmp != 0 {
			return cmp
		}
	}
	return cmpInt(len(left), len(right))
}

func compareLocalPart(left, right pepLocal) int {
	if left.numeric != right.numeric {
		if left.numeric {
			return 1
		}
		return -1
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
