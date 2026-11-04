// Package nmapfinger 把调用方提交的 nmap-service-probes 文档转换成指纹规则。
// Package nmapfinger converts a caller-supplied nmap-service-probes document into fingerprint rules.
//
// 转换不发起网络连接，也不保存探针载荷供以后发送。只有与当前观察刺激等价、并且正则可以被安全执行的 match 和 softmatch 会进入规则包。
// Conversion does not open a network connection and does not store probe payloads for later transmission. Only match and softmatch lines whose stimulus is equivalent to a current observation, and whose regular expression can be executed safely, enter a rule pack.
package nmapfinger

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	// MaxDocumentBytes 是一份服务探针文档的最大字节数。
	// MaxDocumentBytes is the maximum size of one service-probe document.
	MaxDocumentBytes = 4 << 20
	// MaxRules 是一份文档可以转换出的规则数上限。
	// MaxRules is the maximum number of rules one document may convert into.
	MaxRules = 20000
)

// Rule 是一条可以交给指纹引擎的转换结果。
// Rule is one conversion result that can be given to the fingerprint engine.
type Rule struct {
	Key               string
	Probe             string
	Service           string
	Protocol          string
	Pattern           string
	Product           string
	Version           string
	Soft              bool
	Priority          int
	ConfidenceMatched string
	ConfidenceEmpty   string
}

// Report 记录一份文档的许可、接受数量和未进入规则包的原因。
// Report records a document's license, acceptance count, and the reasons lines did not enter the rule pack.
type Report struct {
	Format         string
	DocumentDigest string
	License        string
	Probes         int
	Accepted       int
	ExcludedPorts  bool
	Skipped        map[string]int
}

// Convert 校验并转换 nmap-service-probes 文本。语法错误拒绝整份文档。正则或刺激不能对应时只跳过该行。
// Convert validates and converts nmap-service-probes text. A syntax error rejects the whole document. A line whose regular expression or stimulus does not correspond is skipped.
//
// 文档必须在第一条指令前的注释里包含许可说明。探针载荷不执行。没有可执行规则时返回错误。
// The document must contain a license notice in the comments before the first directive. Probe payloads are not executed. It returns an error when no rule can be executed.
func Convert(document []byte) ([]Rule, Report, error) {
	if len(document) == 0 {
		return nil, Report{}, fmt.Errorf("nmap service probes: document is empty")
	}
	if len(document) > MaxDocumentBytes {
		return nil, Report{}, fmt.Errorf("nmap service probes: document exceeds %d bytes", MaxDocumentBytes)
	}
	if !utf8.Valid(document) || bytes.Contains(document, []byte{0}) {
		return nil, Report{}, fmt.Errorf("nmap service probes: document is not valid text")
	}
	sum := sha256.Sum256(document)
	report := Report{Format: "nmap-service-probes", DocumentDigest: hex.EncodeToString(sum[:]), Skipped: map[string]int{}}
	text := strings.TrimPrefix(string(document), "\uFEFF")
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	license, firstDirective, err := preambleLicense(lines)
	if err != nil {
		return nil, Report{}, err
	}
	report.License = license
	var probe *parsedProbe
	var rules []Rule
	seenProbe := false
	for number := firstDirective; number < len(lines); number++ {
		line := strings.TrimSpace(lines[number])
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "Exclude "):
			report.ExcludedPorts = true
		case strings.HasPrefix(line, "Probe "):
			parsed, err := parseProbe(line, number+1)
			if err != nil {
				return nil, Report{}, err
			}
			probe = parsed
			seenProbe = true
			report.Probes++
		case strings.HasPrefix(line, "match ") || strings.HasPrefix(line, "softmatch "):
			if probe == nil {
				return nil, Report{}, fmt.Errorf("nmap service probes: line %d: match has no probe", number+1)
			}
			parsed, err := parseMatch(line, number+1)
			if err != nil {
				return nil, Report{}, err
			}
			rule, reason, ok := convertMatch(*probe, parsed, len(rules))
			if !ok {
				report.Skipped[reason]++
				continue
			}
			rules = append(rules, rule)
			if len(rules) > MaxRules {
				return nil, Report{}, fmt.Errorf("nmap service probes: more than %d executable rules", MaxRules)
			}
		case isProbeAttribute(line):
			if probe == nil {
				return nil, Report{}, fmt.Errorf("nmap service probes: line %d: attribute has no probe", number+1)
			}
		case strings.HasPrefix(line, "Fingerprint "):
			return nil, Report{}, fmt.Errorf("nmap service probes: line %d: operating-system fingerprints are not service probes", number+1)
		default:
			return nil, Report{}, fmt.Errorf("nmap service probes: line %d: unrecognized directive", number+1)
		}
	}
	if !seenProbe {
		return nil, Report{}, fmt.Errorf("nmap service probes: document has no probe")
	}
	if len(rules) == 0 {
		return nil, Report{}, fmt.Errorf("nmap service probes: no executable rule")
	}
	report.Accepted = len(rules)
	return rules, report, nil
}

func preambleLicense(lines []string) (string, int, error) {
	var comments []string
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			comments = append(comments, trimmed)
			continue
		}
		notice := strings.Join(comments, "\n")
		if !strings.Contains(strings.ToLower(notice), "license") {
			return "", 0, fmt.Errorf("nmap service probes: license notice is missing")
		}
		if len(notice) > 4096 {
			notice = notice[:4096]
		}
		return notice, i, nil
	}
	return "", 0, fmt.Errorf("nmap service probes: document has no directive")
}

type parsedProbe struct {
	Protocol string
	Name     string
	Payload  string
}

type parsedMatch struct {
	Soft     bool
	Service  string
	Pattern  string
	Flags    string
	Product  string
	Version  string
	Captures int
}

func parseProbe(line string, number int) (*parsedProbe, error) {
	rest := strings.TrimSpace(strings.TrimPrefix(line, "Probe "))
	protocol, rest, ok := strings.Cut(rest, " ")
	name, rest, okName := strings.Cut(strings.TrimSpace(rest), " ")
	rest = strings.TrimSpace(rest)
	if !ok || !okName || (protocol != "TCP" && protocol != "UDP") || !namePattern.MatchString(name) || !strings.HasPrefix(rest, "q") {
		return nil, fmt.Errorf("nmap service probes: line %d: malformed probe", number)
	}
	payload, _, err := readDelimited(rest[1:])
	if err != nil {
		return nil, fmt.Errorf("nmap service probes: line %d: malformed probe payload", number)
	}
	decoded, err := unescapePayload(payload)
	if err != nil {
		return nil, fmt.Errorf("nmap service probes: line %d: malformed probe payload", number)
	}
	return &parsedProbe{Protocol: protocol, Name: name, Payload: decoded}, nil
}

func parseMatch(line string, number int) (parsedMatch, error) {
	soft := strings.HasPrefix(line, "softmatch ")
	prefix := "match "
	if soft {
		prefix = "softmatch "
	}
	rest := strings.TrimSpace(line[len(prefix):])
	service, rest, ok := strings.Cut(rest, " ")
	if !ok || !servicePattern.MatchString(service) {
		return parsedMatch{}, fmt.Errorf("nmap service probes: line %d: malformed match", number)
	}
	rest = strings.TrimSpace(rest)
	if !strings.HasPrefix(rest, "m") || len(rest) < 3 {
		return parsedMatch{}, fmt.Errorf("nmap service probes: line %d: malformed match pattern", number)
	}
	pattern, rest, err := readDelimited(rest[1:])
	if err != nil || pattern == "" || len(pattern) > 8192 {
		return parsedMatch{}, fmt.Errorf("nmap service probes: line %d: malformed match pattern", number)
	}
	flags := flagPrefix(rest)
	rest = strings.TrimSpace(rest[len(flags):])
	parsed := parsedMatch{Soft: soft, Service: service, Pattern: pattern, Flags: flags}
	for rest != "" {
		if strings.HasPrefix(rest, "cpe:") {
			_, rest, err = readDelimited(rest[len("cpe:"):])
			if err != nil {
				return parsedMatch{}, fmt.Errorf("nmap service probes: line %d: malformed cpe field", number)
			}
			rest = strings.TrimSpace(rest)
			continue
		}
		if len(rest) < 2 || !fieldInitial(rest[0]) {
			return parsedMatch{}, fmt.Errorf("nmap service probes: line %d: malformed match field", number)
		}
		key := rest[0]
		body, next, err := readDelimited(rest[1:])
		if err != nil {
			return parsedMatch{}, fmt.Errorf("nmap service probes: line %d: malformed match field", number)
		}
		switch key {
		case 'p':
			parsed.Product = body
		case 'v':
			parsed.Version = body
		case 'i', 'h', 'o', 'd':
		default:
			return parsedMatch{}, fmt.Errorf("nmap service probes: line %d: unknown match field", number)
		}
		rest = strings.TrimSpace(next)
	}
	return parsed, nil
}

func convertMatch(probe parsedProbe, match parsedMatch, index int) (Rule, string, bool) {
	protocol, ok := equivalentProtocol(probe, match.Service)
	if !ok {
		if _, mapped := serviceProtocol[strings.ToLower(match.Service)]; !mapped {
			return Rule{}, "service", false
		}
		return Rule{}, "stimulus", false
	}
	for _, flag := range match.Flags {
		if flag != 'i' && flag != 's' {
			return Rule{}, "regex", false
		}
	}
	pattern, reason := executablePattern(match.Pattern, match.Flags)
	if reason != "" {
		return Rule{}, reason, false
	}
	if !match.Soft {
		if reason := templateReason(match.Product, pattern); reason != "" {
			return Rule{}, reason, false
		}
		if reason := templateReason(match.Version, pattern); reason != "" {
			return Rule{}, reason, false
		}
	}
	confidence := "0.6500"
	if match.Soft {
		confidence = "0.6000"
		match.Product = ""
		match.Version = ""
	} else if strings.TrimSpace(match.Product) != "" {
		confidence = "0.8000"
	}
	return Rule{
		Key: fmt.Sprintf("%s/%s/%d", probe.Name, strings.ToLower(match.Service), index), Probe: probe.Name,
		Service: strings.ToLower(match.Service), Protocol: protocol, Pattern: pattern, Product: match.Product,
		Version: match.Version, Soft: match.Soft, Priority: 100 + index, ConfidenceMatched: confidence, ConfidenceEmpty: "0.5500",
	}, "", true
}

func equivalentProtocol(probe parsedProbe, service string) (string, bool) {
	protocol, ok := serviceProtocol[strings.ToLower(service)]
	if !ok || probe.Protocol != "TCP" {
		return "", false
	}
	if probe.Name == "NULL" && probe.Payload == "" && bannerProtocol(protocol) {
		return protocol, true
	}
	if probe.Name == "GetRequest" && probe.Payload == "GET / HTTP/1.0\r\n\r\n" && protocol == "http" {
		return protocol, true
	}
	return "", false
}

func bannerProtocol(protocol string) bool {
	switch protocol {
	case "ssh", "ftp", "smtp", "mysql":
		return true
	default:
		return false
	}
}

var serviceProtocol = map[string]string{
	"ssh": "ssh", "ftp": "ftp", "smtp": "smtp", "mysql": "mysql", "http": "http",
}

func executablePattern(pattern, flags string) (string, string) {
	if unboundedPattern(pattern) {
		return "", "regex"
	}
	if unsupportedConstruct(pattern) {
		return "", "regex"
	}
	compiled := pattern
	if strings.Contains(flags, "s") {
		compiled = "(?s)" + compiled
	}
	if strings.Contains(flags, "i") {
		compiled = "(?i)" + compiled
	}
	compiled = strings.ReplaceAll(compiled, `\0`, `\x00`)
	expression, err := regexp.Compile(compiled)
	if err != nil {
		return "", "regex"
	}
	if expression.NumSubexp() > 9 {
		return "", "regex"
	}
	return compiled, ""
}

func unboundedPattern(pattern string) bool {
	switch strings.TrimSpace(pattern) {
	case ".*", ".+", "^.*", "^.*$", ".*$", "(?s).*", "(?s).+", "[\\s\\S]*", "[\\s\\S]+":
		return true
	default:
		return false
	}
}

func unsupportedConstruct(pattern string) bool {
	for _, token := range []string{"(?=", "(?!", "(?<=", "(?<!", "(?>", "(?("} {
		if strings.Contains(pattern, token) {
			return true
		}
	}
	for i := 0; i < len(pattern)-1; i++ {
		if pattern[i] == '\\' && pattern[i+1] >= '1' && pattern[i+1] <= '9' {
			return true
		}
	}
	return false
}

func templateReason(template, pattern string) string {
	if template == "" {
		return ""
	}
	expression, err := regexp.Compile(pattern)
	if err != nil {
		return "template"
	}
	for i := 0; i < len(template); i++ {
		if template[i] != '$' {
			continue
		}
		if i+1 < len(template) && template[i+1] == '$' {
			i++
			continue
		}
		if i+1 >= len(template) || template[i+1] < '1' || template[i+1] > '9' {
			return "template"
		}
		group, _ := strconv.Atoi(template[i+1 : i+2])
		if group > expression.NumSubexp() {
			return "template"
		}
		i++
	}
	return ""
}

func readDelimited(value string) (string, string, error) {
	if value == "" {
		return "", "", fmt.Errorf("delimiter is missing")
	}
	delimiter := value[0]
	var out strings.Builder
	for i := 1; i < len(value); i++ {
		if value[i] == '\\' && i+1 < len(value) {
			if value[i+1] == delimiter {
				out.WriteByte(delimiter)
			} else {
				out.WriteByte('\\')
				out.WriteByte(value[i+1])
			}
			i++
			continue
		}
		if value[i] == delimiter {
			return out.String(), value[i+1:], nil
		}
		out.WriteByte(value[i])
	}
	return "", "", fmt.Errorf("delimiter is not closed")
}

func unescapePayload(value string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' {
			out.WriteByte(value[i])
			continue
		}
		if i+1 >= len(value) {
			return "", fmt.Errorf("dangling escape")
		}
		switch value[i+1] {
		case 'n':
			out.WriteByte('\n')
		case 'r':
			out.WriteByte('\r')
		case 't':
			out.WriteByte('\t')
		case '0':
			out.WriteByte(0)
		case 'x':
			if i+3 >= len(value) {
				return "", fmt.Errorf("short hex escape")
			}
			decoded, err := hex.DecodeString(value[i+2 : i+4])
			if err != nil {
				return "", err
			}
			out.WriteByte(decoded[0])
			i += 3
			continue
		default:
			out.WriteByte(value[i+1])
		}
		i++
	}
	return out.String(), nil
}

func flagPrefix(value string) string {
	i := 0
	for i < len(value) && value[i] >= 'a' && value[i] <= 'z' {
		i++
	}
	return value[:i]
}

func fieldInitial(value byte) bool {
	switch value {
	case 'p', 'v', 'i', 'h', 'o', 'd':
		return true
	default:
		return false
	}
}

func isProbeAttribute(line string) bool {
	for _, name := range []string{"ports ", "sslports ", "rarity ", "fallback ", "totalwaitms ", "tcpwrappedms "} {
		if strings.HasPrefix(line, name) {
			return true
		}
	}
	return false
}

var (
	namePattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	servicePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
)
