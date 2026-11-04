package probesdk

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/zodirc/Vesper/internal/scope"
)

// ExchangeUDP 在授权和请求预算通过后发送一个 UDP 报文，并读取一个响应报文。
// ExchangeUDP sends one UDP datagram and reads one response after authorization and the request budget succeed.
//
// ip 必须是有效地址。port 取值 1–65535。operation 使用授权模块定义的操作名。payload 不能为空。
// maxResponse 是本次读取的字节上限，超出的报文被截断后返回，不另报错误。
// ip must be a valid address. port is 1–65535. operation uses an operation name defined by the authorization module. payload must not be empty.
// maxResponse is the read limit. A longer datagram is returned truncated and is not reported as a separate error.
//
// 授权失败、预算耗尽或调用方取消时不发送报文。超时返回 ClassTimeout。
// 内核报告 ICMP 端口不可达时返回 ClassICMPUnreachable，不把它改写成关闭。
// 这次发送计入请求预算，不计入连接预算。
// Authorization failure, budget exhaustion, or caller cancellation sends nothing. A timeout returns ClassTimeout.
// An ICMP port-unreachable error reported by the kernel returns ClassICMPUnreachable and is not rewritten as closed.
// The send counts against the request budget, not the connection budget.
func (d Dialer) ExchangeUDP(ctx context.Context, ip netip.Addr, port int, operation string, payload []byte, maxResponse int) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, &Error{Class: ClassCancelled, Message: "udp exchange canceled"}
	}
	ip = ip.Unmap()
	if !ip.IsValid() || port < 1 || port > 65535 || len(payload) == 0 || maxResponse <= 0 {
		return nil, &Error{Class: ClassExecution, Message: "invalid udp exchange"}
	}
	if d.Auth == nil || d.Budget == nil || d.Now == nil {
		return nil, &Error{Class: ClassExecution, Message: "dialer is not initialized"}
	}
	if err := d.Auth.Authorize(ctx, ip, port, "udp", operation); err != nil {
		return nil, &Error{Class: ClassAuthorization, Message: err.Error()}
	}
	if err := d.Budget.AcquireRequest(ctx, d.Now()); err != nil {
		return nil, requestBudgetError(err)
	}
	if err := d.persist(ctx, false); err != nil {
		return nil, err
	}
	network := "udp4"
	if ip.Is6() {
		network = "udp6"
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	// 套接字截止时间使用真实超时，不使用预算时钟。预算时钟可以被注入为固定时间。
	// The socket deadline uses the real timeout, not the budget clock. The budget clock can be injected as a fixed time.
	exchangeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := net.DialUDP(network, nil, &net.UDPAddr{IP: ip.AsSlice(), Port: port})
	if err != nil {
		return nil, udpError(ctx, err)
	}
	defer conn.Close()
	deadline, ok := exchangeCtx.Deadline()
	if !ok {
		return nil, &Error{Class: ClassExecution, Message: "udp exchange has no deadline"}
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, &Error{Class: ClassExecution, Message: err.Error()}
	}
	stop := make(chan struct{})
	go func() {
		select {
		case <-exchangeCtx.Done():
			_ = conn.SetDeadline(time.Unix(0, 1))
		case <-stop:
		}
	}()
	defer close(stop)
	if _, err := conn.Write(payload); err != nil {
		return nil, udpError(ctx, err)
	}
	buf := make([]byte, maxResponse)
	n, err := conn.Read(buf)
	if n > 0 {
		out := make([]byte, n)
		copy(out, buf[:n])
		return out, nil
	}
	if err != nil {
		return nil, udpError(ctx, err)
	}
	return []byte{}, nil
}

func requestBudgetError(err error) error {
	var budgetErr *scope.BudgetError
	if errors.As(err, &budgetErr) {
		return &Error{Class: ClassBudget, Message: budgetErr.Error()}
	}
	if errors.Is(err, context.Canceled) {
		return &Error{Class: ClassCancelled, Message: err.Error()}
	}
	return &Error{Class: ClassExecution, Message: err.Error()}
}

func udpError(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		return &Error{Class: ClassCancelled, Message: "udp exchange canceled"}
	}
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return &Error{Class: ClassTimeout, Message: "udp exchange timed out"}
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return &Error{Class: ClassICMPUnreachable, Message: "icmp port unreachable"}
	}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		return &Error{Class: ClassNetworkUnreachable, Message: err.Error()}
	}
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return &Error{Class: ClassPermission, Message: err.Error()}
	}
	return &Error{Class: ClassExecution, Message: err.Error()}
}
