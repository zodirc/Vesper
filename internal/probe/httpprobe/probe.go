// Package httpprobe 对已授权的 IP 执行有界 HTTP 请求，不跟随会改变目标地址的重定向。
// Package httpprobe performs a bounded HTTP request to an authorized IP and does not follow a redirect that would change the target address.
package httpprobe

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

// Result 是一次 HTTP 探测的结构化结果。
// Result is the structured result of one HTTP probe.
type Result struct {
	StatusCode int
	Reason     string
	Headers    map[string]string
	Body       []byte
	Raw        []byte
	State      string
	Message    string
}

// Probe 发送一个 HTTP/1.0 GET 并限制响应字节数。
// Probe sends one HTTP/1.0 GET and limits the response size.
//
// hostname 只写入 Host 头，不参与 TCP 连接。maxBytes 包含状态行、头部和正文。
// hostname is written only to the Host header and is not used for the TCP connection. maxBytes includes the status line, headers, and body.
func Probe(ctx context.Context, dial probesdk.Dialer, budget interface {
	AcquireRequest(context.Context, time.Time) error
}, ip netip.Addr, port int, hostname string, maxBytes int, now func() time.Time) (Result, error) {
	if maxBytes <= 0 {
		return Result{State: "error", Message: "read limit must be positive"}, &probesdk.Error{Class: probesdk.ClassExecution, Message: "read limit must be positive"}
	}
	if err := budget.AcquireRequest(ctx, now()); err != nil {
		return Result{State: "not_scanned", Message: err.Error()}, err
	}
	conn, err := dial.DialTCP(ctx, ip, port, "protocol_probe")
	if err != nil {
		return Result{State: probesdk.Classify(err), Message: err.Error()}, err
	}
	defer conn.Close()
	host := hostname
	if host == "" {
		host = ip.String()
	}
	request := fmt.Sprintf("GET / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\nUser-Agent: vesper-probe\r\n\r\n", host)
	_ = conn.SetDeadline(time.Now().Add(dial.Timeout))
	if _, err := conn.Write([]byte(request)); err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	raw, err := readAtMost(conn, maxBytes)
	if len(raw) == 0 && err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	status, reason, headers, body := parse(raw)
	return Result{StatusCode: status, Reason: reason, Headers: headers, Body: body, Raw: raw, State: "open"}, nil
}

func readAtMost(conn net.Conn, maxBytes int) ([]byte, error) {
	buf := make([]byte, maxBytes)
	total := 0
	for total < maxBytes {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return buf[:total], err
		}
		if n == 0 {
			break
		}
	}
	return buf[:total], nil
}

func parse(raw []byte) (int, string, map[string]string, []byte) {
	reader := bufio.NewReader(bytes.NewReader(raw))
	line, err := reader.ReadString('\n')
	if err != nil && len(line) == 0 {
		return 0, "", map[string]string{}, raw
	}
	fields := strings.Fields(strings.TrimSpace(line))
	status := 0
	reason := ""
	if len(fields) >= 2 {
		status, _ = strconv.Atoi(fields[1])
	}
	if len(fields) >= 3 {
		reason = strings.Join(fields[2:], " ")
	}
	headers := map[string]string{}
	for {
		header, readErr := reader.ReadString('\n')
		header = strings.TrimSpace(header)
		if header == "" {
			break
		}
		name, value, ok := strings.Cut(header, ":")
		if ok {
			headers[strings.ToLower(strings.TrimSpace(name))] = strings.TrimSpace(value)
		}
		if readErr != nil {
			break
		}
	}
	body, _ := io.ReadAll(reader)
	return status, reason, headers, body
}
