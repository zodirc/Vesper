package activedetect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// MaxTemplateBytes 是单份模板原文的上限。
	// MaxTemplateBytes is the limit for one template document.
	MaxTemplateBytes = 256 << 10
	// MaxRequestBound 是一份模板在执行前可以确定的请求数上限。
	// MaxRequestBound is the maximum request count that can be fixed before execution.
	MaxRequestBound = 8
)

var templateKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var cvePattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// Template 是一份通过结构校验、请求数可以预先确定的 Nuclei HTTP 模板。
// Template is a Nuclei HTTP template that passed structural checks and has a request count fixed in advance.
type Template struct {
	Key          string
	Name         string
	Severity     string
	CVE          string
	RequestBound int
	Digest       string
	Body         []byte
}

// Admit 校验调用方提交的模板原文。通过时返回可入库的模板，不访问网络。
// Admit checks a caller-submitted template document. On success it returns a template that can be stored, and it does not use the network.
//
// 只接受顶层为 id、info、http 的文档。http 请求必须能在执行前数清，路径只能指向本次目标。code、headless、file、javascript、network、dns、workflow、fuzz、payload、interactsh 和会离开目标的重定向都不接受。
// Only a document whose top-level keys are id, info, and http is accepted. HTTP requests must be countable before execution, and paths must stay on this target. code, headless, file, javascript, network, dns, workflow, fuzz, payload, interactsh, and redirects that can leave the target are rejected.
func Admit(body []byte) (Template, error) {
	if len(body) == 0 || len(body) > MaxTemplateBytes {
		return Template{}, fmt.Errorf("admit template: size %d", len(body))
	}
	if !utf8Valid(body) {
		return Template{}, fmt.Errorf("admit template: body is not utf-8")
	}
	lower := strings.ToLower(string(body))
	for _, word := range []string{"interactsh", "oast", "file://"} {
		if strings.Contains(lower, word) {
			return Template{}, fmt.Errorf("admit template: %s is not executable", word)
		}
	}
	var root map[string]any
	if err := yaml.Unmarshal(body, &root); err != nil {
		return Template{}, fmt.Errorf("admit template: %w", err)
	}
	if len(root) == 0 {
		return Template{}, fmt.Errorf("admit template: empty document")
	}
	for key := range root {
		switch key {
		case "id", "info", "http":
		default:
			return Template{}, fmt.Errorf("admit template: %s is not executable", key)
		}
	}
	key, ok := root["id"].(string)
	if !ok || !templateKeyPattern.MatchString(key) {
		return Template{}, fmt.Errorf("admit template: id is invalid")
	}
	info, ok := root["info"].(map[string]any)
	if !ok {
		return Template{}, fmt.Errorf("admit template: info is missing")
	}
	name, _ := info["name"].(string)
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, "\r\n") {
		return Template{}, fmt.Errorf("admit template: name is invalid")
	}
	severity := normalizeSeverity(stringField(info["severity"]))
	cve, err := oneCVE(info["classification"])
	if err != nil {
		return Template{}, err
	}
	requests, ok := root["http"].([]any)
	if !ok || len(requests) == 0 {
		return Template{}, fmt.Errorf("admit template: http requests are missing")
	}
	bound := 0
	for _, item := range requests {
		block, ok := item.(map[string]any)
		if !ok {
			return Template{}, fmt.Errorf("admit template: http request is invalid")
		}
		count, err := countRequest(block)
		if err != nil {
			return Template{}, err
		}
		bound += count
	}
	if bound < 1 || bound > MaxRequestBound {
		return Template{}, fmt.Errorf("admit template: request bound %d", bound)
	}
	sum := sha256.Sum256(body)
	return Template{
		Key: key, Name: name, Severity: severity, CVE: cve, RequestBound: bound,
		Digest: hex.EncodeToString(sum[:]), Body: append([]byte(nil), body...),
	}, nil
}

func countRequest(block map[string]any) (int, error) {
	for key := range block {
		switch key {
		case "method", "path", "headers", "body", "matchers", "matchers-condition", "extractors", "stop-at-first-match":
		case "redirects":
			enabled, ok := block[key].(bool)
			if !ok || enabled {
				return 0, fmt.Errorf("admit template: redirects are not executable")
			}
		default:
			return 0, fmt.Errorf("admit template: http %s is not executable", key)
		}
	}
	methods, err := methodsOf(block["method"])
	if err != nil {
		return 0, err
	}
	paths, ok := block["path"].([]any)
	if !ok || len(paths) == 0 {
		return 0, fmt.Errorf("admit template: path is missing")
	}
	for _, item := range paths {
		path, ok := item.(string)
		if !ok {
			return 0, fmt.Errorf("admit template: path is invalid")
		}
		if err := cleanPath(path); err != nil {
			return 0, err
		}
	}
	if text, ok := block["body"].(string); ok && len(text) > 4096 {
		return 0, fmt.Errorf("admit template: request body is too large")
	}
	if err := headersStayOnTarget(block["headers"]); err != nil {
		return 0, err
	}
	return len(methods) * len(paths), nil
}

func methodsOf(value any) ([]string, error) {
	if value == nil {
		return []string{"GET"}, nil
	}
	switch typed := value.(type) {
	case string:
		if !allowedMethod(typed) {
			return nil, fmt.Errorf("admit template: method %s", typed)
		}
		return []string{strings.ToUpper(typed)}, nil
	case []any:
		if len(typed) == 0 {
			return nil, fmt.Errorf("admit template: method is empty")
		}
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			text, ok := item.(string)
			if !ok || !allowedMethod(text) {
				return nil, fmt.Errorf("admit template: method is invalid")
			}
			out = append(out, strings.ToUpper(text))
		}
		return out, nil
	default:
		return nil, fmt.Errorf("admit template: method is invalid")
	}
}

func allowedMethod(value string) bool {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS":
		return true
	default:
		return false
	}
}

func cleanPath(path string) error {
	if strings.Contains(path, "://") || strings.HasPrefix(path, "//") {
		return fmt.Errorf("admit template: path leaves the target")
	}
	rest := path
	if strings.HasPrefix(rest, "{{BaseURL}}") {
		rest = strings.TrimPrefix(rest, "{{BaseURL}}")
	}
	if strings.Contains(rest, "{{") || strings.Contains(rest, "}}") || !strings.HasPrefix(rest, "/") {
		return fmt.Errorf("admit template: path %s", path)
	}
	return nil
}

func headersStayOnTarget(value any) error {
	if value == nil {
		return nil
	}
	headers, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("admit template: headers are invalid")
	}
	for key := range headers {
		if strings.EqualFold(key, "host") {
			return fmt.Errorf("admit template: host header is set by the executor")
		}
	}
	return nil
}

func oneCVE(value any) (string, error) {
	info, ok := value.(map[string]any)
	if !ok || info["cve-id"] == nil {
		return "", nil
	}
	switch typed := info["cve-id"].(type) {
	case string:
		if !cvePattern.MatchString(typed) {
			return "", fmt.Errorf("admit template: cve-id is invalid")
		}
		return typed, nil
	case []any:
		if len(typed) != 1 {
			return "", nil
		}
		text, ok := typed[0].(string)
		if !ok || !cvePattern.MatchString(text) {
			return "", fmt.Errorf("admit template: cve-id is invalid")
		}
		return text, nil
	default:
		return "", fmt.Errorf("admit template: cve-id is invalid")
	}
}

func normalizeSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "info", "low", "medium", "high", "critical":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func stringField(value any) string {
	text, _ := value.(string)
	return text
}

func utf8Valid(body []byte) bool {
	return strings.ToValidUTF8(string(body), "") == string(body)
}
