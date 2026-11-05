package zgrab2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
)

// Module 是一个 ZGrab2 模块的归一化结果。完整 JSON 留在证据里，不进入识别引擎。
// Module is the normalized result of one ZGrab2 module. The full JSON stays in evidence and does not enter the identification engine.
type Module struct {
	Name       string
	Status     string
	HTTPStatus int
	TLSVersion string
}

// Report 是一次单目标输出。
// Report is the output for one target.
type Report struct {
	IP      netip.Addr
	Modules []Module
}

// Parse 读取一行 ZGrab2 JSON。IP 必须等于授权目标，且只能出现 http 和 tls。
// Parse reads one ZGrab2 JSON line. The IP must equal the authorized target, and only http and tls may appear.
func Parse(raw []byte, expect netip.Addr) (Report, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || !expect.IsValid() {
		return Report{}, fmt.Errorf("%w: output is empty", ErrRejected)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var body struct {
		IP   string                     `json:"ip"`
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := decoder.Decode(&body); err != nil {
		return Report{}, fmt.Errorf("%w: %v", ErrRejected, err)
	}
	if decoder.More() {
		return Report{}, fmt.Errorf("%w: more than one target", ErrRejected)
	}
	got, err := netip.ParseAddr(body.IP)
	if err != nil || got.Unmap() != expect.Unmap() {
		return Report{}, fmt.Errorf("%w: target mismatch", ErrRejected)
	}
	if len(body.Data) != ModuleCount() {
		return Report{}, fmt.Errorf("%w: module set mismatch", ErrRejected)
	}
	report := Report{IP: got.Unmap()}
	for _, name := range []string{"http", "tls"} {
		encoded, ok := body.Data[name]
		if !ok {
			return Report{}, fmt.Errorf("%w: module %s missing", ErrRejected, name)
		}
		module, err := parseModule(name, encoded)
		if err != nil {
			return Report{}, err
		}
		report.Modules = append(report.Modules, module)
	}
	return report, nil
}

func parseModule(name string, raw json.RawMessage) (Module, error) {
	var body struct {
		Status string          `json:"status"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return Module{}, fmt.Errorf("%w: %s: %v", ErrRejected, name, err)
	}
	if body.Status == "" {
		return Module{}, fmt.Errorf("%w: %s status is empty", ErrRejected, name)
	}
	module := Module{Name: name, Status: body.Status}
	if name == "http" {
		module.HTTPStatus = httpStatus(body.Result)
	}
	if name == "tls" {
		module.TLSVersion = tlsVersion(body.Result)
	}
	return module, nil
}

func httpStatus(raw json.RawMessage) int {
	var body struct {
		Response struct {
			StatusCode int `json:"status_code"`
		} `json:"response"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return 0
	}
	if body.Response.StatusCode < 100 || body.Response.StatusCode > 599 {
		return 0
	}
	return body.Response.StatusCode
}

func tlsVersion(raw json.RawMessage) string {
	var body struct {
		HandshakeLog struct {
			ServerHello struct {
				Version struct {
					Name string `json:"name"`
				} `json:"version"`
			} `json:"server_hello"`
		} `json:"handshake_log"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return ""
	}
	name := body.HandshakeLog.ServerHello.Version.Name
	if stringsHasControl(name) || len(name) > 32 {
		return ""
	}
	return name
}

func stringsHasControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// ResultStatus 把模块状态收成观察允许的结果。
// ResultStatus folds module statuses into a result the observation table accepts.
//
// 观察结果没有 conflict。目标不一致在 Parse 阶段拒绝，不进入这里。
// Observation results have no conflict status. A target mismatch is rejected by Parse and does not reach this function.
func ResultStatus(modules []Module) string {
	if len(modules) == 0 {
		return "error"
	}
	success, timedOut := 0, 0
	for _, module := range modules {
		switch module.Status {
		case "success":
			success++
		case "io-timeout", "connection-timeout":
			timedOut++
		}
	}
	switch {
	case success == len(modules):
		return "observed"
	case timedOut == len(modules):
		return "no_response"
	case success > 0:
		return "partial"
	default:
		return "error"
	}
}
