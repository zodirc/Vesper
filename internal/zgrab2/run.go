package zgrab2

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

const maxOutputBytes = 256 << 10

// Run 对一个已授权地址执行固定的 HTTP 和 TLS 抓取。
// Run performs the fixed HTTP and TLS grab against one authorized address.
//
// 进程的标准输入只有 CommandLine 返回的那一行。标准输出超过 256 KiB 时停止读取并结束进程。标准错误只保留前 4 KiB，解析失败时附在错误里。
// The process receives only the single line returned by CommandLine on standard input. Reading stops after 256 KiB of standard output and the process is ended. Standard error keeps its first 4 KiB and is attached to the error when parsing fails.
func Run(ctx context.Context, ip netip.Addr, port int, hostname string) (Report, []byte, error) {
	binary, err := Binary()
	if err != nil {
		return Report{}, nil, err
	}
	args, stdin, err := CommandLine(binary, ip, port, hostname)
	if err != nil {
		return Report{}, nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(TimeoutSeconds*ModuleCount()+5)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdin = bytes.NewReader([]byte(stdin + "\n"))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Report{}, nil, fmt.Errorf("zgrab2 start: %w", err)
	}
	stderr := &capBuffer{max: 4 << 10}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return Report{}, nil, fmt.Errorf("zgrab2 start: %w", err)
	}
	raw, readErr := readLimited(stdout)
	if readErr != nil {
		cancel()
	}
	waitErr := cmd.Wait()
	if readErr != nil {
		return Report{}, raw, fmt.Errorf("zgrab2 output: %w", readErr)
	}
	report, parseErr := Parse(raw, ip)
	if parseErr != nil {
		if detail := strings.TrimSpace(stderr.String()); detail != "" {
			return Report{}, raw, fmt.Errorf("%w; stderr: %s", parseErr, detail)
		}
		return Report{}, raw, parseErr
	}
	if waitErr != nil && ctx.Err() != nil {
		return report, raw, ctx.Err()
	}
	return report, raw, nil
}

// capBuffer 保留标准错误的前一段，并丢弃其余字节，避免外部进程把内存写满。
// capBuffer keeps a prefix of standard error and discards the rest, so the external process cannot fill memory.
type capBuffer struct {
	buf bytes.Buffer
	max int
}

func (c *capBuffer) Write(p []byte) (int, error) {
	remain := c.max - c.buf.Len()
	if remain > 0 {
		if len(p) > remain {
			_, _ = c.buf.Write(p[:remain])
		} else {
			_, _ = c.buf.Write(p)
		}
	}
	return len(p), nil
}

func (c *capBuffer) String() string {
	return c.buf.String()
}

func readLimited(reader io.Reader) ([]byte, error) {
	limited := io.LimitReader(reader, maxOutputBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return raw, err
	}
	if len(raw) > maxOutputBytes {
		return raw[:maxOutputBytes], fmt.Errorf("zgrab2 output exceeds %d bytes", maxOutputBytes)
	}
	return raw, nil
}
