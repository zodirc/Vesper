// Package udp 定义协议化 UDP 探测的结论边界。没有请求和响应规则时，结果保持 unknown。
// Package udp defines the conclusion boundary of a protocol-specific UDP probe. Without a request and response rule, the result remains unknown.
package udp

import "fmt"

// Spec 描述一种有界 UDP 探针能够支持的最强结论。
// Spec describes the strongest conclusion one bounded UDP probe is allowed to make.
type Spec struct {
	Name                 string
	Request              []byte
	MaxRequestBytes      int
	ResponseMatches      func([]byte) bool
	ICMPUnreachableMeans string
	TimeoutConclusion    string
}

// Outcome 是 UDP 探针依据响应或错误能够得出的结论。
// Outcome is the conclusion a UDP probe can draw from a response or an error.
type Outcome struct {
	State   string
	Status  string
	Message string
}

// Evaluate 按探针规格解释响应。空请求不会被解释为端口关闭。
// Evaluate interprets a response according to the probe spec. An empty request is not interpreted as a closed port.
func Evaluate(spec Spec, response []byte, icmpUnreachable bool, timedOut bool) (Outcome, error) {
	if spec.Name == "" || len(spec.Request) == 0 || spec.ResponseMatches == nil {
		return Outcome{State: "unknown", Status: "unsupported", Message: "udp probe has no protocol request"}, fmt.Errorf("udp probe %q: protocol request is required", spec.Name)
	}
	if spec.MaxRequestBytes > 0 && len(spec.Request) > spec.MaxRequestBytes {
		return Outcome{State: "unknown", Status: "error", Message: "udp request exceeds limit"}, fmt.Errorf("udp probe %q: request exceeds %d bytes", spec.Name, spec.MaxRequestBytes)
	}
	if icmpUnreachable {
		state := spec.ICMPUnreachableMeans
		if state == "" {
			state = "unknown"
		}
		return Outcome{State: state, Status: "unreachable"}, nil
	}
	if timedOut {
		state := spec.TimeoutConclusion
		if state == "" {
			state = "no_response"
		}
		return Outcome{State: state, Status: "no_response"}, nil
	}
	if spec.ResponseMatches(response) {
		return Outcome{State: "open", Status: "observed"}, nil
	}
	return Outcome{State: "unknown", Status: "observed", Message: "response did not match the probe rule"}, nil
}
