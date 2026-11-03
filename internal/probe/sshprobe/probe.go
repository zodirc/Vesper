// Package sshprobe 读取 SSH 标识行，不用端口号推断 SSH 服务。
// Package sshprobe reads the SSH identification line and does not infer an SSH service from the port number.
package sshprobe

import (
	"bufio"
	"context"
	"net/netip"
	"strings"
	"time"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

// Result 是 SSH 标识行观察。
// Result is an SSH identification-line observation.
type Result struct {
	Banner  string
	Raw     []byte
	IsSSH   bool
	State   string
	Message string
}

// Probe 在连接成功后最多读取 255 字节标识行。
// Probe reads at most 255 bytes of the identification line after the connection succeeds.
func Probe(ctx context.Context, dial probesdk.Dialer, budget interface {
	AcquireRequest(context.Context, time.Time) error
}, ip netip.Addr, port int, now func() time.Time) (Result, error) {
	if err := budget.AcquireRequest(ctx, now()); err != nil {
		return Result{State: "not_scanned", Message: err.Error()}, err
	}
	conn, err := dial.DialTCP(ctx, ip, port, "protocol_probe")
	if err != nil {
		return Result{State: probesdk.Classify(err), Message: err.Error()}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dial.Timeout))
	reader := bufio.NewReaderSize(conn, 255)
	line, err := reader.ReadSlice('\n')
	if len(line) > 255 {
		line = line[:255]
	}
	banner := strings.TrimSpace(string(line))
	if len(line) == 0 && err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	return Result{Banner: banner, Raw: append([]byte(nil), line...), IsSSH: strings.HasPrefix(banner, "SSH-"), State: "open"}, nil
}
