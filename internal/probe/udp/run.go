package udp

import (
	"context"
	"errors"
	"fmt"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

// Run 按探针规格收发 UDP。规格不完整时不调用 exchange。
// Run exchanges UDP according to the probe spec. It does not call exchange when the spec is incomplete.
//
// 只有超时会继续下一次，次数不超过 Attempts。ICMP 结论、授权失败、预算耗尽、取消、网络不可达和执行错误都停止。
// 授权失败、预算耗尽和取消的 Rounds 为 0。超时不能得出 closed 或 open。
// Only a timeout continues, and the number of attempts does not exceed Attempts. An ICMP conclusion, authorization failure, budget exhaustion, cancellation, network unreachability, and an execution error all stop.
// Authorization failure, budget exhaustion, and cancellation leave Rounds at 0. A timeout cannot conclude closed or open.
func Run(ctx context.Context, spec Spec, exchange func(context.Context, []byte) ([]byte, error)) (Result, error) {
	if err := validate(spec); err != nil {
		return Result{Outcome: Outcome{State: "unknown", Status: "not_scanned", Message: err.Error()}}, err
	}
	if exchange == nil {
		return Result{}, fmt.Errorf("udp probe %s: exchange is required", spec.Name)
	}
	base := Result{Probe: spec.Name, Version: spec.Version, Query: append([]byte(nil), spec.Request...)}
	var last Outcome
	for round := 1; round <= spec.Attempts; round++ {
		if ctx.Err() != nil {
			base.Outcome = Outcome{State: "not_scanned", Status: "not_scanned", Message: ctx.Err().Error()}
			return base, nil
		}
		response, err := exchange(ctx, spec.Request)
		if err == nil {
			outcome, evalErr := Evaluate(spec, response, false, false)
			if evalErr != nil {
				return Result{}, evalErr
			}
			base.Outcome = outcome
			base.Response = response
			base.Rounds = round
			return base, nil
		}
		outcome, stop, decided := exchangeOutcome(spec, err)
		if !decided {
			return Result{}, err
		}
		if stop {
			base.Outcome = outcome
			base.Rounds = roundsAfterSend(outcome.State, round)
			return base, nil
		}
		last = outcome
		base.Rounds = round
	}
	base.Outcome = last
	return base, nil
}

// Execute 按已注册的探针名称运行。没有注册探针时不发送报文，结论是 unknown。
// Execute runs a registered probe by name. When no probe is registered it sends nothing and the conclusion is unknown.
//
// 当前注册的探针是 DNS 和 NTP。qname 只供 DNS 选择查询名称。
// The registered probes are DNS and NTP. qname is used only by DNS to choose the query name.
func Execute(ctx context.Context, name string, exchange func(context.Context, []byte) ([]byte, error), qname string) (Result, error) {
	switch name {
	case DNSName:
		return ProbeDNS(ctx, exchange, qname)
	case NTPName:
		return ProbeNTP(ctx, exchange)
	default:
		return Result{Outcome: Outcome{State: "unknown", Status: "not_scanned", Message: "udp probe has no protocol request"}}, nil
	}
}

// ResponseLimit 返回已注册探针的响应读取上限。没有注册探针时返回 0。
// ResponseLimit returns the response read limit of a registered probe. It returns 0 when no probe is registered.
func ResponseLimit(name string) int {
	switch name {
	case DNSName:
		return DNSMaxResponseBytes
	case NTPName:
		return NTPPacketBytes
	default:
		return 0
	}
}

func exchangeOutcome(spec Spec, err error) (Outcome, bool, bool) {
	var probeErr *probesdk.Error
	if !errors.As(err, &probeErr) {
		if errors.Is(err, context.Canceled) {
			return Outcome{State: "not_scanned", Status: "not_scanned", Message: err.Error()}, true, true
		}
		return Outcome{}, false, false
	}
	switch probeErr.Class {
	case probesdk.ClassTimeout:
		outcome, evalErr := Evaluate(spec, nil, false, true)
		if evalErr != nil {
			return Outcome{}, false, false
		}
		if outcome.Message == "" {
			outcome.Message = "timeout"
		}
		return outcome, false, true
	case probesdk.ClassICMPUnreachable:
		outcome, evalErr := Evaluate(spec, nil, true, false)
		if evalErr != nil {
			return Outcome{}, false, false
		}
		return outcome, true, true
	case probesdk.ClassNetworkUnreachable:
		return Outcome{State: "unreachable", Status: "unreachable", Message: probeErr.Error()}, true, true
	case probesdk.ClassAuthorization, probesdk.ClassBudget, probesdk.ClassCancelled:
		return Outcome{State: "not_scanned", Status: "not_scanned", Message: probeErr.Error()}, true, true
	case probesdk.ClassPermission, probesdk.ClassUnsupported:
		return Outcome{State: "unsupported", Status: "unsupported", Message: probeErr.Error()}, true, true
	default:
		return Outcome{State: "error", Status: "error", Message: probeErr.Error()}, true, true
	}
}

func roundsAfterSend(state string, round int) int {
	if state == "not_scanned" {
		return 0
	}
	return round
}
