package activedetect

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

const requestTimeoutSeconds = 10

// CommandLine 构造一次 Nuclei 调用的参数。参数只来自已审核模板文件、授权目标和授权速率。
// CommandLine builds one Nuclei invocation. The arguments come only from the reviewed template file, the authorized target, and the authorized rate.
//
// 不接收调用方拼接的命令行。重定向、Interactsh、模板更新和其他协议都被关掉。
// It does not accept a command line assembled by the caller. Redirects, Interactsh, template updates, and other protocols are disabled.
func CommandLine(binary, templatePath string, target netip.Addr, port int, hostname string, ratePerSecond int) ([]string, error) {
	if binary == "" || templatePath == "" || !target.IsValid() || port < 1 || port > 65535 {
		return nil, fmt.Errorf("nuclei command: target is invalid")
	}
	if strings.ContainsAny(hostname, "\r\n ") {
		return nil, fmt.Errorf("nuclei command: hostname is invalid")
	}
	if ratePerSecond < 1 {
		ratePerSecond = 1
	}
	args := []string{
		binary,
		"-t", templatePath,
		"-u", targetURL(target, port),
		"-jsonl",
		"-silent",
		"-disable-update-check",
		"-no-interactsh",
		"-disable-redirects",
		"-retries", "0",
		"-timeout", strconv.Itoa(requestTimeoutSeconds),
		"-rate-limit", strconv.Itoa(ratePerSecond),
		"-concurrency", "1",
		"-bulk-size", "1",
		"-exclude-protocols", "code,headless,file,javascript,network,dns,ssl,websocket,whois,tcp",
	}
	if hostname != "" {
		args = append(args, "-H", "Host: "+hostname)
	}
	return args, nil
}

func targetURL(target netip.Addr, port int) string {
	host := target.String()
	if target.Is6() {
		host = "[" + host + "]"
	}
	return "http://" + host + ":" + strconv.Itoa(port) + "/"
}
