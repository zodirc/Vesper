package assess

import (
	"strconv"
	"strings"
)

// Maven 版本使用 maven-artifact 的 ComparableVersion。限定符顺序是 alpha、beta、milestone、rc、snapshot、正式版、sp。未知限定符排在已知限定符之后，并按 ASCII 比较。
// Maven versions use the ComparableVersion algorithm from maven-artifact. Qualifier order is alpha, beta, milestone, rc, snapshot, release, then sp. Unknown qualifiers sort after the known ones and compare as ASCII.

var mavenQualifiers = []string{"alpha", "beta", "milestone", "rc", "snapshot", "", "sp"}

const mavenRelease = 5

type mvnItem interface {
	cmp(other mvnItem) int
	nullish() bool
	format(out *strings.Builder, first bool)
}

type mvnList struct {
	items []mvnItem
}

type mvnInt struct {
	n int
}

type mvnStr struct {
	s string
}

func normalizeMaven(raw string) (string, bool) {
	list, ok := parseMaven(raw)
	if !ok {
		return "", false
	}
	var b strings.Builder
	for i, item := range list.items {
		item.format(&b, i == 0)
	}
	if b.Len() == 0 {
		return "0", true
	}
	return b.String(), true
}

func compareMaven(left, right string) (int, bool) {
	a, aok := parseMaven(left)
	b, bok := parseMaven(right)
	if !aok || !bok {
		return 0, false
	}
	return a.cmp(b), true
}

func parseMaven(raw string) (*mvnList, bool) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" || strings.ContainsAny(raw, " \t") {
		return nil, false
	}
	root := &mvnList{}
	stack := []*mvnList{root}
	list := root
	digit := false
	start := 0
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c == '.':
			if !appendToken(list, raw[start:i], digit) {
				return nil, false
			}
			start = i + 1
		case c == '-':
			if !appendToken(list, raw[start:i], digit) {
				return nil, false
			}
			start = i + 1
			list = &mvnList{}
			stack[len(stack)-1].items = append(stack[len(stack)-1].items, list)
			stack = append(stack, list)
		case c >= '0' && c <= '9':
			if !digit && i > start {
				if !appendString(list, raw[start:i], true) {
					return nil, false
				}
				start = i
				list = pushList(list)
				stack = append(stack, list)
			}
			digit = true
		default:
			if digit && i > start {
				if !appendToken(list, raw[start:i], true) {
					return nil, false
				}
				start = i
				list = pushList(list)
				stack = append(stack, list)
			}
			digit = false
		}
	}
	if start <= len(raw) {
		if !appendToken(list, raw[start:], digit) {
			return nil, false
		}
	}
	for i := len(stack) - 1; i >= 0; i-- {
		stack[i].normalize()
	}
	return root, true
}

func pushList(current *mvnList) *mvnList {
	next := &mvnList{}
	current.items = append(current.items, next)
	return next
}

func appendToken(list *mvnList, token string, digit bool) bool {
	if token == "" {
		list.items = append(list.items, &mvnInt{})
		return true
	}
	if digit {
		number, err := strconv.Atoi(token)
		if err != nil {
			return false
		}
		list.items = append(list.items, &mvnInt{n: number})
		return true
	}
	return appendString(list, token, false)
}

func appendString(list *mvnList, token string, followedByDigit bool) bool {
	if token == "" {
		return false
	}
	if followedByDigit && len(token) == 1 {
		switch token {
		case "a":
			token = "alpha"
		case "b":
			token = "beta"
		case "m":
			token = "milestone"
		}
	}
	switch token {
	case "ga", "final", "release":
		token = ""
	case "cr":
		token = "rc"
	}
	list.items = append(list.items, &mvnStr{s: token})
	return true
}

func (l *mvnList) normalize() {
	for _, item := range l.items {
		if child, ok := item.(*mvnList); ok {
			child.normalize()
		}
	}
	for len(l.items) > 0 && l.items[len(l.items)-1].nullish() {
		l.items = l.items[:len(l.items)-1]
	}
}

func (l *mvnList) nullish() bool {
	return len(l.items) == 0
}

func (l *mvnList) cmp(other mvnItem) int {
	if other == nil {
		if len(l.items) == 0 {
			return 0
		}
		return l.items[0].cmp(nil)
	}
	switch v := other.(type) {
	case *mvnInt:
		return -1
	case *mvnStr:
		return 1
	case *mvnList:
		return compareMavenItems(l.items, v.items)
	default:
		return 1
	}
}

func (n *mvnInt) nullish() bool { return n.n == 0 }

func (n *mvnInt) cmp(other mvnItem) int {
	if other == nil {
		if n.n == 0 {
			return 0
		}
		return 1
	}
	switch v := other.(type) {
	case *mvnInt:
		return cmpInt(n.n, v.n)
	default:
		return 1
	}
}

func (s *mvnStr) nullish() bool { return s.s == "" }

func (s *mvnStr) cmp(other mvnItem) int {
	if other == nil {
		if index, ok := mavenIndex(s.s); ok {
			return index - mavenRelease
		}
		return 1
	}
	switch v := other.(type) {
	case *mvnInt:
		return -1
	case *mvnList:
		return -1
	case *mvnStr:
		return compareMavenQualifier(s.s, v.s)
	default:
		return -1
	}
}

func compareMavenItems(left, right []mvnItem) int {
	n := len(left)
	if len(right) > n {
		n = len(right)
	}
	for i := 0; i < n; i++ {
		var a, b mvnItem
		if i < len(left) {
			a = left[i]
		}
		if i < len(right) {
			b = right[i]
		}
		if cmp := compareMavenItem(a, b); cmp != 0 {
			return cmp
		}
	}
	return 0
}

func compareMavenItem(left, right mvnItem) int {
	if left == nil && right == nil {
		return 0
	}
	if left == nil {
		return -right.cmp(nil)
	}
	return left.cmp(right)
}

func compareMavenQualifier(left, right string) int {
	li, lok := mavenIndex(left)
	ri, rok := mavenIndex(right)
	switch {
	case lok && rok:
		return cmpInt(li, ri)
	case lok:
		return -1
	case rok:
		return 1
	}
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func mavenIndex(value string) (int, bool) {
	for i, item := range mavenQualifiers {
		if item == value {
			return i, true
		}
	}
	return 0, false
}

func (n *mvnInt) format(out *strings.Builder, first bool) {
	if !first {
		out.WriteByte('.')
	}
	out.WriteString(strconv.Itoa(n.n))
}

func (s *mvnStr) format(out *strings.Builder, first bool) {
	if s.s == "" {
		return
	}
	if !first {
		out.WriteByte('.')
	}
	out.WriteString(s.s)
}

func (l *mvnList) format(out *strings.Builder, first bool) {
	if len(l.items) == 0 {
		return
	}
	out.WriteByte('-')
	for i, item := range l.items {
		item.format(out, i == 0)
	}
}
