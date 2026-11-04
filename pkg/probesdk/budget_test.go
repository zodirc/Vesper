package probesdk

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/scope"
)

func TestPersistBudgetFailureDoesNotDial(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- struct{}{}
			_ = conn.Close()
		}
	}()
	account := scope.NewAccount(scope.Budget{MaxConnections: 2, MaxRequests: 2, MaxRatePerSecond: 1000, MaxRuntime: time.Minute}, time.Now().UTC())
	dialer := Dialer{
		Auth: allowAll{}, Budget: account, Timeout: time.Second, Now: time.Now,
		PersistBudget: func(context.Context) error { return errors.New("budget store unavailable") },
	}
	_, err = dialer.DialTCP(context.Background(), listenerAddr(t, listener), listenerPort(t, listener), "connect")
	var probeErr *Error
	if err == nil || !errors.As(err, &probeErr) {
		t.Fatalf("err = %v", err)
	}
	if account.ExportUsage().Connections != 0 {
		t.Fatalf("connections = %d", account.ExportUsage().Connections)
	}
	select {
	case <-accepted:
		t.Fatal("dial started after the budget write failed")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestPersistBudgetRunsBeforeTheDial(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()
	account := scope.NewAccount(scope.Budget{MaxConnections: 2, MaxRequests: 2, MaxRatePerSecond: 1000, MaxRuntime: time.Minute}, time.Now().UTC())
	saw := 0
	dialer := Dialer{
		Auth: allowAll{}, Budget: account, Timeout: time.Second, Now: time.Now,
		PersistBudget: func(context.Context) error {
			saw = int(account.ExportUsage().Connections)
			return nil
		},
	}
	conn, err := dialer.DialTCP(context.Background(), listenerAddr(t, listener), listenerPort(t, listener), "connect")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if saw != 1 || account.ExportUsage().Connections != 1 {
		t.Fatalf("persisted = %d final = %d", saw, account.ExportUsage().Connections)
	}
}

type allowAll struct{}

func (allowAll) Authorize(context.Context, netip.Addr, int, string, string) error { return nil }

func listenerAddr(t *testing.T, listener net.Listener) netip.Addr {
	t.Helper()
	host, _, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

func listenerPort(t *testing.T, listener net.Listener) int {
	t.Helper()
	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return port
}
