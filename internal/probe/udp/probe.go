// Package udp 执行有请求和响应规则的 UDP 探针。当前只发送 DNS 查询。
// Package udp runs UDP probes that have a request and a response rule. It currently sends only DNS queries.
//
// 没有探针的端口保持 unknown，不发送报文。超时不能写成 closed。
// A port without a probe stays unknown and is not sent a packet. A timeout cannot be recorded as closed.
package udp

import "fmt"

// Spec 描述一种有界 UDP 探针的请求、响应规则和结论上限。
// Spec describes the request, response rule, and conclusion ceiling of one bounded UDP probe.
//
// 发送前必须具备名称、非空请求、请求和响应长度上限、至少一次尝试、响应识别函数、ICMP 结论和超时结论。
// Before a packet is sent it must have a name, a non-empty request, request and response limits, at least one attempt, a response matcher, an ICMP conclusion, and a timeout conclusion.
type Spec struct {
	Name                 string
	Version              string
	Request              []byte
	MaxRequestBytes      int
	MaxResponseBytes     int
	Attempts             int
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
//
// 超时结论只能是 no_response 或 unknown。ICMP 端口不可达不能得出 open。
// A timeout conclusion can only be no_response or unknown. ICMP port unreachable cannot conclude open.
func Evaluate(spec Spec, response []byte, icmpUnreachable bool, timedOut bool) (Outcome, error) {
	if err := validate(spec); err != nil {
		return Outcome{State: "unknown", Status: "not_scanned", Message: err.Error()}, err
	}
	if icmpUnreachable {
		state := spec.ICMPUnreachableMeans
		if state == "" || state == "unknown" {
			return Outcome{State: "unknown", Status: "unreachable"}, nil
		}
		if state == "closed" {
			return Outcome{State: state, Status: "observed"}, nil
		}
		return Outcome{State: state, Status: state}, nil
	}
	if timedOut {
		state := spec.TimeoutConclusion
		if state == "" {
			state = "no_response"
		}
		if state != "no_response" && state != "unknown" {
			return Outcome{State: "no_response", Status: "no_response"}, fmt.Errorf("udp probe %q: timeout cannot conclude %s", spec.Name, spec.TimeoutConclusion)
		}
		return Outcome{State: state, Status: "no_response"}, nil
	}
	if spec.ResponseMatches(response) {
		return Outcome{State: "open", Status: "observed"}, nil
	}
	return Outcome{State: "unknown", Status: "observed", Message: "response did not match the probe rule"}, nil
}

func validate(spec Spec) error {
	if spec.Name == "" || len(spec.Request) == 0 || spec.ResponseMatches == nil {
		return fmt.Errorf("udp probe %q: protocol request is required", spec.Name)
	}
	if spec.MaxRequestBytes < len(spec.Request) || spec.MaxResponseBytes <= 0 || spec.Attempts < 1 {
		return fmt.Errorf("udp probe %q: request, response limit, or attempts are invalid", spec.Name)
	}
	switch spec.TimeoutConclusion {
	case "", "no_response", "unknown":
	default:
		return fmt.Errorf("udp probe %q: timeout cannot conclude %s", spec.Name, spec.TimeoutConclusion)
	}
	switch spec.ICMPUnreachableMeans {
	case "", "unknown", "closed", "unreachable", "no_response":
	default:
		return fmt.Errorf("udp probe %q: icmp cannot conclude %s", spec.Name, spec.ICMPUnreachableMeans)
	}
	return nil
}
