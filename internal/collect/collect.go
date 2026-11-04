// Package collect 通过固定操作采集本机信息。未实现的操作返回 unsupported，不用空结果表示平台不支持。
// Package collect gathers local host facts through fixed operations. An unimplemented operation returns unsupported and does not use an empty result to mean the platform lacks support.
package collect

const (
	// StatusCollected 表示采集成功且取得数据。
	// StatusCollected means collection succeeded and produced data.
	StatusCollected = "collected"
	// StatusEmpty 表示采集成功且结果确实为空。
	// StatusEmpty means collection succeeded and the result is genuinely empty.
	StatusEmpty = "empty"
	// StatusPermissionDenied 表示权限不足。
	// StatusPermissionDenied means the permission is insufficient.
	StatusPermissionDenied = "permission_denied"
	// StatusUnsupported 表示平台或操作未实现。
	// StatusUnsupported means the platform or operation is not implemented.
	StatusUnsupported = "unsupported"
	// StatusError 表示系统接口返回错误。
	// StatusError means a system interface returned an error.
	StatusError = "error"
	// StatusNotRequested 表示本次任务没有要求该操作。
	// StatusNotRequested means this task did not request the operation.
	StatusNotRequested = "not_requested"
)

// Operations 是允许出现在采集任务中的固定操作。
// Operations are the fixed operations allowed in a collection task.
var Operations = []string{
	"collect_os_info",
	"collect_interfaces",
	"collect_listening_sockets",
	"collect_processes",
	"collect_services",
	"collect_packages",
	"collect_firewall_config",
}

// Result 是一项固定采集操作的结果。
// Result is the result of one fixed collection operation.
type Result struct {
	Operation       string
	Status          string
	Value           map[string]any
	MachineIDHash   string
	PlatformFamily  string
	PlatformName    string
	PlatformVersion string
}

// CollectRequested 执行请求的操作，并为未请求的固定操作返回 not_requested。
// CollectRequested executes the requested operations and returns not_requested for fixed operations that were not requested.
func CollectRequested(requested []string) ([]Result, error) {
	wanted := map[string]struct{}{}
	for _, op := range requested {
		wanted[op] = struct{}{}
	}
	var out []Result
	for _, op := range Operations {
		if _, ok := wanted[op]; !ok {
			out = append(out, Result{Operation: op, Status: StatusNotRequested})
			continue
		}
		item, err := collectPlatform(op)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}

// HashText 计算主机标识摘要，调用方不得保存原始标识。
// HashText computes a host-identifier digest. The caller must not store the raw identifier.
func HashText(text string) string {
	return hashText(text)
}
