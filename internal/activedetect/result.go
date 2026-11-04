package activedetect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Verdict 是对一份 Nuclei JSONL 输出的校验结论。
// Verdict is the validation result for one Nuclei JSONL output.
type Verdict struct {
	Status    string
	MatchedAt string
}

// ParseOutput 校验执行器输出。模板标识或目标地址与本次调用不一致时结论是 conflict，并且不把该输出当作漏洞成立。
// ParseOutput validates executor output. When the template identifier or target address differs from this invocation, the verdict is conflict and the output is not treated as a confirmed vulnerability.
//
// 没有命中行时结论是 unknown。严重性以入库时的模板记录为准，不采用输出里的严重性。
// The verdict is unknown when no match line is present. Severity stays on the stored template record and is not taken from the output.
func ParseOutput(output []byte, templateKey string, target netip.Addr, port int, hostname string) (Verdict, error) {
	if templateKey == "" || !target.IsValid() || port < 1 || port > 65535 {
		return Verdict{}, fmt.Errorf("parse nuclei output: target is invalid")
	}
	matched := false
	matchedAt := ""
	for _, line := range bytes.Split(output, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal(line, &event); err != nil {
			return Verdict{Status: "conflict"}, nil
		}
		if !matchLine(event) {
			continue
		}
		if stringField(event["template-id"]) != templateKey && stringField(event["templateID"]) != templateKey {
			return Verdict{Status: "conflict"}, nil
		}
		location := stringField(event["matched-at"])
		if location == "" {
			location = stringField(event["matched_at"])
		}
		if !sameTarget(location, target, port, hostname) {
			return Verdict{Status: "conflict"}, nil
		}
		matched = true
		matchedAt = location
	}
	if !matched {
		return Verdict{Status: "unknown"}, nil
	}
	return Verdict{Status: "confirmed", MatchedAt: matchedAt}, nil
}

func matchLine(event map[string]any) bool {
	switch value := event["matcher-status"].(type) {
	case bool:
		return value
	case string:
		return strings.EqualFold(value, "true")
	default:
		return stringField(event["matched-at"]) != "" || stringField(event["matched_at"]) != ""
	}
}

func sameTarget(raw string, target netip.Addr, port int, hostname string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" {
		return false
	}
	host := parsed.Hostname()
	gotPort := parsed.Port()
	if gotPort == "" {
		gotPort = "80"
	}
	if gotPort != strconv.Itoa(port) {
		return false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap() == target.Unmap()
	}
	return hostname != "" && strings.EqualFold(host, hostname)
}
