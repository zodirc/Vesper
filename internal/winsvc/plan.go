// Package winsvc 把 vesperd 注册为 Windows Service，并响应服务控制管理器的停止和关机。
// Package winsvc registers vesperd as a Windows Service and answers stop and shutdown from the service control manager.
package winsvc

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

const (
	// Name 是服务控制管理器中的服务名。
	// Name is the service name in the service control manager.
	Name = "vesperd"
	// DisplayName 是服务管理单元中的显示名。
	// DisplayName is the name shown in the service management console.
	DisplayName = "Vesper"
	// Description 是服务配置里的说明。
	// Description is the text stored in the service configuration.
	Description = "Vesper 本机控制服务，负责任务、授权、扫描执行和结果。"
	// Account 是服务进程账户。主机采集需要读取本机服务、注册表、进程命令行和防火墙。
	// Account is the service process account. Host collection reads local services, the registry, process command lines, and the firewall.
	Account = "LocalSystem"
	// Dependency 是启动前必须已经运行的服务。
	// Dependency is the service that must already be running before start.
	Dependency = "Tcpip"

	// StartHint 是向服务控制管理器申报的启动等待时间。
	// StartHint is the start wait reported to the service control manager.
	StartHint = 30 * time.Second
	// StopHint 是停止和预关机等待时间。
	// StopHint is the wait for stop and preshutdown.
	StopHint = 20 * time.Second
	// StateWait 是 install、start、stop 和 uninstall 等待状态变化的最长时间。
	// StateWait is how long install, start, stop, and uninstall wait for a state change.
	StateWait = 2 * time.Minute
	// RecoveryReset 是连续无失败后把失败计数清零的时间。
	// RecoveryReset is the failure-free interval after which the failure count returns to zero.
	RecoveryReset = 24 * time.Hour
)

// ErrUnsupported 表示当前操作系统不能注册 Windows Service。
// ErrUnsupported means this operating system cannot register a Windows Service.
var ErrUnsupported = errors.New("windows service control is only available on Windows")

// ErrConfig 表示安装服务所需的环境不完整或含有不能写入注册表的字符。
// ErrConfig means the environment required to install the service is incomplete or contains characters that cannot be stored in the registry.
var ErrConfig = errors.New("windows service configuration is incomplete")

// ErrFailed 表示服务没有进入请求的状态。
// ErrFailed means the service did not reach the requested state.
var ErrFailed = errors.New("windows service operation failed")

// ErrTimeout 表示等待服务状态变化超时。
// ErrTimeout means waiting for a service state change timed out.
var ErrTimeout = errors.New("windows service state change timed out")

// ErrAccess 表示调用者没有服务控制管理器所需的管理员权限。
// ErrAccess means the caller lacks the administrator rights required by the service control manager.
var ErrAccess = errors.New("windows service control requires an elevated administrator")

// RecoveryDelays 是失败后的重启间隔。超过次数后，服务控制管理器重复最后一档。
// RecoveryDelays are the restart intervals after failure. After the last entry, the service control manager repeats it.
func RecoveryDelays() []time.Duration {
	return []time.Duration{5 * time.Second, 30 * time.Second, 60 * time.Second}
}

// KnownCommand 报告 name 是不是服务管理子命令。
// KnownCommand reports whether name is a service-management subcommand.
func KnownCommand(name string) bool {
	switch name {
	case "install", "uninstall", "start", "stop":
		return true
	default:
		return false
	}
}

// PlanEnvironment 生成写入服务 Environment 的 NAME=VALUE 列表。
// PlanEnvironment builds the NAME=VALUE list written to the service Environment value.
//
// lookup 只读取调用方给出的环境。cwd 用来解析已经设置的相对路径，executable 所在目录用来解析未设置的证据目录和迁移目录。
// lookup reads only the environment supplied by the caller. cwd resolves relative paths that are already set. The directory containing executable resolves an evidence or migration directory that is not set.
//
// 必需变量缺失、路径不是绝对路径，或值含有 NUL、CR、LF 时返回 ErrConfig。
// It returns ErrConfig when a required variable is missing, a path is not absolute, or a value contains NUL, CR, or LF.
func PlanEnvironment(lookup func(string) string, cwd, executable string) ([]string, error) {
	if lookup == nil {
		return nil, fmt.Errorf("%w: environment is missing", ErrConfig)
	}
	if !filepath.IsAbs(executable) {
		return nil, fmt.Errorf("%w: executable path is not absolute", ErrConfig)
	}
	work, err := filepath.Abs(cwd)
	if err != nil {
		return nil, err
	}
	exeDir := filepath.Dir(executable)
	lines := make([]string, 0, 8)
	for _, key := range []string{"VESPER_ADMIN_USER", "VESPER_ADMIN_PASSWORD", "VESPER_DATABASE_URL"} {
		line, err := entry(key, lookup(key))
		if err != nil {
			return nil, err
		}
		lines = append(lines, line)
	}
	if value := lookup("VESPER_LISTEN"); value != "" {
		line, err := entry("VESPER_LISTEN", value)
		if err != nil {
			return nil, err
		}
		lines = append(lines, line)
	}
	evidence := lookup("VESPER_EVIDENCE_DIR")
	if evidence == "" {
		evidence = filepath.Join(exeDir, "var", "evidence")
	} else if !filepath.IsAbs(evidence) {
		evidence = filepath.Join(work, evidence)
	}
	evidence, err = filepath.Abs(evidence)
	if err != nil {
		return nil, err
	}
	migration := lookup("VESPER_MIGRATION")
	if migration == "" {
		migration = filepath.Join(exeDir, "migrations")
	} else if !filepath.IsAbs(migration) {
		migration = filepath.Join(work, migration)
	}
	migration, err = filepath.Abs(migration)
	if err != nil {
		return nil, err
	}
	for _, key := range []string{"VESPER_EVIDENCE_DIR", "VESPER_MIGRATION"} {
		value := evidence
		if key == "VESPER_MIGRATION" {
			value = migration
		}
		line, err := entry(key, value)
		if err != nil {
			return nil, err
		}
		lines = append(lines, line)
	}
	for _, key := range []string{"VESPER_NUCLEI", "VESPER_ZGRAB2", "NVD_API_KEY"} {
		value := lookup(key)
		if value == "" {
			continue
		}
		if key != "NVD_API_KEY" && !filepath.IsAbs(value) {
			return nil, fmt.Errorf("%w: %s is not absolute", ErrConfig, key)
		}
		line, err := entry(key, value)
		if err != nil {
			return nil, err
		}
		lines = append(lines, line)
	}
	return lines, nil
}

func entry(key, value string) (string, error) {
	if value == "" || strings.ContainsAny(value, "\x00\r\n") {
		return "", fmt.Errorf("%w: %s", ErrConfig, key)
	}
	return key + "=" + value, nil
}

// Redact 从 message 中去掉 secrets 里的非空字符串。
// Redact removes non-empty strings in secrets from message.
func Redact(message string, secrets []string) string {
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		message = strings.ReplaceAll(message, secret, "***")
	}
	if len(message) > 2048 {
		message = message[:2048]
	}
	return message
}

// Secrets 返回事件日志中需要遮盖的环境值。
// Secrets returns environment values that must be masked in the event log.
func Secrets(lookup func(string) string) []string {
	if lookup == nil {
		return nil
	}
	var secrets []string
	for _, key := range []string{"VESPER_ADMIN_PASSWORD", "VESPER_DATABASE_URL", "NVD_API_KEY"} {
		if value := lookup(key); value != "" {
			secrets = append(secrets, value)
		}
	}
	return secrets
}
