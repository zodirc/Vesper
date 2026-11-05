package zgrab2

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

const (
	// TimeoutSeconds 是传给 ZGrab2 的单次连接超时。
	// TimeoutSeconds is the per-connection timeout passed to ZGrab2.
	TimeoutSeconds = 10
	// HTTPReadKiB 是 HTTP 响应读取上限，与自研 HTTP 探针的 4096 字节同一量级。
	// HTTPReadKiB is the HTTP response read ceiling, the same order of magnitude as the native HTTP probe's 4096 bytes.
	HTTPReadKiB = 4
)

// CommandLine 构造一次只含 HTTP 和 TLS 的 ZGrab2 调用。
// CommandLine builds one ZGrab2 invocation that contains only HTTP and TLS.
//
// 参数不接受调用方拼接。不跟随重定向，不把明文 HTTP 重试成 HTTPS，不发送 Heartbleed。
// SMTP、SSH、Telnet、NTP、SMB 等模块不在参数中：它们的默认交换超出已经记录的探针边界。
// The caller cannot append arguments. Redirects are not followed, plaintext HTTP is not retried as HTTPS, and Heartbleed is not sent.
// SMTP, SSH, Telnet, NTP, SMB, and similar modules are absent: their default exchanges exceed the recorded probe bounds.
//
// 标准输入只有已授权的 IP。hostname 只在不含逗号、空白和控制字符时写入同一行，供 Host 和 SNI 使用，不触发再次解析。
// Standard input carries only the authorized IP. hostname is written on that same line, for Host and SNI, only when it has no comma, whitespace, or control character. It does not cause another lookup.
func CommandLine(binary string, ip netip.Addr, port int, hostname string) (args []string, stdin string, err error) {
	if binary == "" || !ip.IsValid() || port < 1 || port > 65535 {
		return nil, "", fmt.Errorf("zgrab2 command: target is invalid")
	}
	host := grabHostname(hostname)
	target := ip.String()
	if host != "" {
		target += "," + host
	}
	portText := strconv.Itoa(port)
	args = []string{
		binary,
		"--senders=1",
		"--gomaxprocs=1",
		"--timeout=" + strconv.Itoa(TimeoutSeconds),
		"http",
		"--port=" + portText,
		"--method=GET",
		"--endpoint=/",
		"--user-agent=Vesper",
		"--max-size=" + strconv.Itoa(HTTPReadKiB),
		"--max-redirects=0",
		"--no-http2",
		"tls",
		"--port=" + portText,
	}
	if host != "" {
		args = append(args, "--server-name="+host)
	}
	return args, target, nil
}

// ModuleCount 是一次调用会打开的连接数，也是要预留的请求数。
// ModuleCount is the number of connections one invocation opens and the number of requests to reserve.
func ModuleCount() int {
	return 2
}

func grabHostname(host string) string {
	if host == "" || len(host) > 253 {
		return ""
	}
	for _, r := range host {
		if r < 0x20 || r == 0x7f || r == ',' || r == ' ' || r == '\\' || r == '"' {
			return ""
		}
	}
	if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") || strings.Contains(host, "..") {
		return ""
	}
	return host
}
