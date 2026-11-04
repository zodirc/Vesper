// Package tcp 使用 Connect 扫描生成端口状态，不把超时改写成过滤或关闭。
// Package tcp produces port states with connect scans and does not rewrite a timeout as filtered or closed.
package tcp

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

// Result 是一个端口的 Connect 扫描结果。
// Result is the connect-scan result of one port.
type Result struct {
	Port       int
	State      string
	Error      string
	ObservedAt time.Time
}

// Scan 按有限并发对同一 IP 的端口执行 Connect 扫描。
// Scan runs a connect scan against ports on one IP with bounded concurrency.
//
// operation 是这次拨号提交给授权校验的操作名，取 discovery 或 connect。空操作名不拨号。
// operation is the authorization operation submitted for each dial. It is discovery or connect. An empty operation does not dial.
//
// 尚未开始的端口在取消后记为 not_scanned。连接被拒绝记为 closed，超时记为 no_response。
// Ports that have not started are recorded as not_scanned after cancellation. A refused connection is closed, and a timeout is no_response.
func Scan(ctx context.Context, dial probesdk.Dialer, ip netip.Addr, ports []int, concurrency int, operation string, now func() time.Time) []Result {
	results := make([]Result, len(ports))
	if operation == "" {
		observed := now().UTC()
		for i, port := range ports {
			results[i] = Result{Port: port, State: "error", Error: "dial operation is empty", ObservedAt: observed}
		}
		return results
	}
	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, port := range ports {
		if ctx.Err() != nil {
			results[i] = Result{Port: port, State: "not_scanned", ObservedAt: now().UTC()}
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(index, port int) {
			defer wg.Done()
			defer func() { <-sem }()
			results[index] = dialOne(ctx, dial, ip, port, operation, now)
		}(i, port)
	}
	wg.Wait()
	return results
}

func dialOne(ctx context.Context, dial probesdk.Dialer, ip netip.Addr, port int, operation string, now func() time.Time) Result {
	observed := now().UTC()
	if ctx.Err() != nil {
		return Result{Port: port, State: "not_scanned", ObservedAt: observed}
	}
	conn, err := dial.DialTCP(ctx, ip, port, operation)
	if err != nil {
		return Result{Port: port, State: probesdk.Classify(err), Error: err.Error(), ObservedAt: observed}
	}
	_ = conn.Close()
	return Result{Port: port, State: "open", ObservedAt: observed}
}

// Reachability 根据一组端口结果归纳主机发现结论，不把单一无响应写成离线。
// Reachability summarizes host discovery from port results and does not rewrite a single no-response as offline.
func Reachability(results []Result) string {
	sawNoResponse := false
	sawUnreachable := false
	sawError := false
	for _, result := range results {
		switch result.State {
		case "open", "closed":
			return "reachable"
		case "no_response":
			sawNoResponse = true
		case "unreachable":
			sawUnreachable = true
		case "error":
			sawError = true
		}
	}
	switch {
	case sawError:
		return "error"
	case sawUnreachable && !sawNoResponse:
		return "unreachable"
	case sawNoResponse:
		return "no_response"
	default:
		return "not_attempted"
	}
}

// Ensure the net import remains available for callers that classify raw network errors in tests.
var _ = net.ErrClosed
