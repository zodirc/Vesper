package scope

import (
	"context"
	"sync"
	"time"
)

// Account 在执行端本地累计预算消耗。
// Account accumulates budget consumption locally on the executor.
type Account struct {
	mu          sync.Mutex
	limit       Budget
	started     time.Time
	connections int64
	requests    int64
	addresses   int64
	targets     int64
	evidence    int64
	nextAllowed time.Time
}

// NewAccount 从起始时间创建本地预算账本。
// NewAccount creates a local budget ledger from the start time.
func NewAccount(limit Budget, started time.Time) *Account {
	return &Account{limit: limit, started: started.UTC()}
}

// TryTarget 占用一个目标名额。
// TryTarget reserves one target slot.
func (a *Account) TryTarget() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.targets >= a.limit.MaxTargets {
		return errBudget("max_targets")
	}
	a.targets++
	return nil
}

// TryAddress 占用一个解析地址名额。
// TryAddress reserves one resolved-address slot.
func (a *Account) TryAddress() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.addresses >= a.limit.MaxAddresses {
		return errBudget("max_addresses")
	}
	a.addresses++
	return nil
}

// AcquireConnection 占用一次连接尝试，并按速率上限等待。
// AcquireConnection reserves one connection attempt and waits for the rate ceiling.
//
// 超过连接次数或运行时长时立即拒绝，不等待。取消上下文会中止速率等待。
// It rejects immediately when the connection count or runtime is exhausted. A canceled context aborts rate waiting.
func (a *Account) AcquireConnection(ctx context.Context, now time.Time) error {
	return a.acquire(ctx, now, true)
}

// AcquireRequest 占用一次协议请求。
// AcquireRequest reserves one protocol request.
func (a *Account) AcquireRequest(ctx context.Context, now time.Time) error {
	return a.acquire(ctx, now, false)
}

func (a *Account) acquire(ctx context.Context, now time.Time, connection bool) error {
	now = now.UTC()
	a.mu.Lock()
	if a.limit.MaxRuntime > 0 && now.Sub(a.started) >= a.limit.MaxRuntime {
		a.mu.Unlock()
		return errBudget("max_runtime")
	}
	if connection && a.connections >= a.limit.MaxConnections {
		a.mu.Unlock()
		return errBudget("max_connections")
	}
	if !connection && a.requests >= a.limit.MaxRequests {
		a.mu.Unlock()
		return errBudget("max_requests")
	}
	wait := time.Duration(0)
	if a.limit.MaxRatePerSecond > 0 {
		gap := time.Duration(float64(time.Second) / a.limit.MaxRatePerSecond)
		if now.Before(a.nextAllowed) {
			wait = a.nextAllowed.Sub(now)
		}
		base := now
		if wait > 0 {
			base = a.nextAllowed
		}
		a.nextAllowed = base.Add(gap)
	}
	if connection {
		a.connections++
	} else {
		a.requests++
	}
	a.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// TryEvidence 占用证据字节额度。
// TryEvidence reserves evidence bytes.
func (a *Account) TryEvidence(n int64) error {
	if n < 0 {
		return errBudget("evidence_size")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.evidence+n > a.limit.MaxEvidenceBytes {
		return errBudget("max_evidence_bytes")
	}
	a.evidence += n
	return nil
}

// BudgetError 表示本地预算拒绝了一次消耗。
// BudgetError means the local budget rejected a consumption attempt.
type BudgetError struct {
	Dimension string
}

func (e *BudgetError) Error() string {
	return "budget exhausted: " + e.Dimension
}

func errBudget(dimension string) error {
	return &BudgetError{Dimension: dimension}
}

// Usage 是预算账本的可恢复计数。
// Usage is the recoverable counter set of a budget ledger.
type Usage struct {
	Started     time.Time
	Targets     int64
	Addresses   int64
	Connections int64
	Requests    int64
	Evidence    int64
	NextAllowed time.Time
}

// ExportUsage 返回当前计数副本。
// ExportUsage returns a copy of the current counters.
func (a *Account) ExportUsage() Usage {
	a.mu.Lock()
	defer a.mu.Unlock()
	return Usage{
		Started: a.started, Targets: a.targets, Addresses: a.addresses, Connections: a.connections,
		Requests: a.requests, Evidence: a.evidence, NextAllowed: a.nextAllowed,
	}
}

// RestoreUsage 用已持久化的计数恢复账本，不改变上限。
// RestoreUsage restores persisted counters without changing the ceiling.
func (a *Account) RestoreUsage(usage Usage) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.started = usage.Started.UTC()
	a.targets = usage.Targets
	a.addresses = usage.Addresses
	a.connections = usage.Connections
	a.requests = usage.Requests
	a.evidence = usage.Evidence
	a.nextAllowed = usage.NextAllowed.UTC()
}
