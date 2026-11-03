// Package probesdk 为探针提供授权校验、预算、受控连接和错误分类。
// Package probesdk provides probes with authorization checks, budgets, controlled connections, and error classification.
//
// 连接入口只接受 IP。探针不能把域名交给操作系统解析器。
// The connection entry accepts only an IP. A probe cannot hand a hostname to the operating system resolver.
package probesdk

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	"github.com/zodirc/Vesper/internal/scope"
)

const (
	// ClassAuthorization 表示授权拒绝，此阶段不得发起网络操作。
	// ClassAuthorization means authorization denied the operation. No network operation may start.
	ClassAuthorization = "authorization_denied"
	// ClassBudget 表示本地预算已耗尽。
	// ClassBudget means the local budget is exhausted.
	ClassBudget = "budget_exhausted"
	// ClassCancelled 表示调用方取消了执行。
	// ClassCancelled means the caller canceled execution.
	ClassCancelled = "cancelled"
	// ClassTimeout 表示操作超时。超时不是目标离线结论。
	// ClassTimeout means the operation timed out. A timeout is not a conclusion that the target is offline.
	ClassTimeout = "timeout"
	// ClassUnsupported 表示当前平台或探针没有该能力。
	// ClassUnsupported means the current platform or probe does not have the capability.
	ClassUnsupported = "unsupported"
	// ClassPermission 表示操作系统权限不足。
	// ClassPermission means the operating system permission is insufficient.
	ClassPermission = "permission_denied"
	// ClassExecution 表示执行失败。初始化失败使用该分类，不得伪装成无响应。
	// ClassExecution means execution failed. Initialization failure uses this class and must not be disguised as no response.
	ClassExecution = "execution_error"
	// ClassEvidence 表示证据没有完成持久化和摘要校验。
	// ClassEvidence means evidence persistence or digest verification did not complete.
	ClassEvidence = "evidence_failed"
)

// Error 是带稳定分类的探针错误。
// Error is a probe error with a stable class.
type Error struct {
	Class   string
	Message string
}

// Error 返回分类和说明。
// Error returns the class and message.
func (e *Error) Error() string {
	return e.Class + ": " + e.Message
}

// Classify 把连接错误映射为端口状态。取消和授权失败不映射为无响应或关闭。
// Classify maps a connection error to a port state. Cancellation and authorization failure are not mapped to no response or closed.
func Classify(err error) string {
	if err == nil {
		return "open"
	}
	var probeErr *Error
	if errors.As(err, &probeErr) {
		switch probeErr.Class {
		case ClassTimeout:
			return "no_response"
		case ClassAuthorization, ClassBudget, ClassCancelled:
			return "not_scanned"
		case ClassUnsupported, ClassPermission:
			return "unsupported"
		default:
			return "error"
		}
	}
	if errors.Is(err, context.Canceled) {
		return "not_scanned"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "no_response"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "no_response"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "closed"
	}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		return "unreachable"
	}
	return "error"
}

// Authorizer 在连接前校验最终 IP、端口、传输协议和操作。
// Authorizer checks the final IP, port, transport, and operation before a connection.
type Authorizer interface {
	Authorize(ctx context.Context, ip netip.Addr, port int, transport, operation string) error
}

// Dialer 是受控 TCP 连接入口。
// Dialer is the controlled TCP connection entry.
type Dialer struct {
	Auth    Authorizer
	Budget  *scope.Account
	Timeout time.Duration
	Now     func() time.Time
}

// DialTCP 在授权和预算通过后连接指定 IP。
// DialTCP connects to the given IP after authorization and budget checks succeed.
//
// ip 必须是有效地址。port 取值 1–65535。operation 使用授权模块定义的操作名。
// ip must be a valid address. port is 1–65535. operation uses an operation name defined by the authorization module.
//
// 授权失败时返回 ClassAuthorization，且不会调用网络拨号。
// On authorization failure it returns ClassAuthorization and does not dial.
func (d Dialer) DialTCP(ctx context.Context, ip netip.Addr, port int, operation string) (net.Conn, error) {
	if !ip.IsValid() || port < 1 || port > 65535 {
		return nil, &Error{Class: ClassExecution, Message: "invalid dial target"}
	}
	if d.Auth == nil || d.Budget == nil || d.Now == nil {
		return nil, &Error{Class: ClassExecution, Message: "dialer is not initialized"}
	}
	if err := d.Auth.Authorize(ctx, ip.Unmap(), port, "tcp", operation); err != nil {
		return nil, &Error{Class: ClassAuthorization, Message: err.Error()}
	}
	if err := d.Budget.AcquireConnection(ctx, d.Now()); err != nil {
		var budgetErr *scope.BudgetError
		if errors.As(err, &budgetErr) {
			return nil, &Error{Class: ClassBudget, Message: budgetErr.Error()}
		}
		if errors.Is(err, context.Canceled) {
			return nil, &Error{Class: ClassCancelled, Message: err.Error()}
		}
		return nil, &Error{Class: ClassExecution, Message: err.Error()}
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(ip.Unmap().String(), strconv.Itoa(port)))
	if err == nil {
		return conn, nil
	}
	if errors.Is(dialCtx.Err(), context.DeadlineExceeded) && errors.Is(ctx.Err(), context.Canceled) {
		return nil, &Error{Class: ClassCancelled, Message: "dial canceled"}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return nil, &Error{Class: ClassTimeout, Message: "dial timed out"}
	}
	return nil, err
}

// ReadLimited 从连接读取至多 maxBytes，并受上下文截止时间约束。
// ReadLimited reads at most maxBytes from the connection and honors the context deadline.
func ReadLimited(ctx context.Context, conn net.Conn, maxBytes int) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, &Error{Class: ClassExecution, Message: "read limit must be positive"}
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	buf := make([]byte, maxBytes)
	n, err := conn.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	if err != nil {
		return nil, fmt.Errorf("read probe response: %w", err)
	}
	return []byte{}, nil
}
