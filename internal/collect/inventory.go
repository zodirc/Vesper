package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	// cmdlineLimit 是单个进程命令行保留的最大字节数。
	// cmdlineLimit is the maximum number of command-line bytes kept for one process.
	cmdlineLimit = 512
	// textLimit 是防火墙规则文本保留的最大字节数。
	// textLimit is the maximum number of firewall rule bytes kept.
	textLimit = 256 * 1024
)

// ReadProcesses 读取 root 下的数字目录，把它当作 /proc 进程表。
// ReadProcesses reads numeric directories under root and treats them as the /proc process table.
//
// root 必须是进程目录。命令行中的 NUL 转为空格，超过 512 字节时截断并设置 cmdline_truncated。进程在读取期间退出则跳过。单个进程不可读时计入 unreadable，不丢弃其余进程。
// root must be the process directory. NUL bytes in a command line become spaces. A command line longer than 512 bytes is truncated and cmdline_truncated is set. A process that exits during the read is skipped. An unreadable process increments unreadable and does not discard the other processes.
//
// root 无法打开时返回错误。进程目录存在但状态字段无法解析时返回错误。
// It returns an error when root cannot be opened. It returns an error when a process directory exists but its state field cannot be parsed.
func ReadProcesses(root string) ([]map[string]any, int, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, 0, err
	}
	var records []map[string]any
	unreadable := 0
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		command, err := os.ReadFile(filepath.Join(dir, "comm"))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			if os.IsPermission(err) {
				unreadable++
				continue
			}
			return nil, 0, fmt.Errorf("read process %d command: %w", pid, err)
		}
		stat, err := os.ReadFile(filepath.Join(dir, "stat"))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			if os.IsPermission(err) {
				unreadable++
				continue
			}
			return nil, 0, fmt.Errorf("read process %d state: %w", pid, err)
		}
		state, ok := processState(string(stat))
		if !ok {
			return nil, 0, fmt.Errorf("read process %d state: malformed stat", pid)
		}
		cmdline, truncated, err := readCmdline(filepath.Join(dir, "cmdline"))
		if err != nil {
			if os.IsNotExist(err) {
				cmdline = ""
			} else if os.IsPermission(err) {
				unreadable++
				continue
			} else {
				return nil, 0, fmt.Errorf("read process %d command line: %w", pid, err)
			}
		}
		item := map[string]any{"pid": pid, "command": strings.TrimSpace(string(command)), "cmdline": cmdline, "state": state}
		if truncated {
			item["cmdline_truncated"] = true
		}
		records = append(records, item)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i]["pid"].(int) < records[j]["pid"].(int)
	})
	return records, unreadable, nil
}

func readCmdline(path string) (string, bool, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return "", false, err
	}
	text, truncated := boundCommandLine(strings.ReplaceAll(string(body), "\x00", " "))
	return text, truncated, nil
}

func boundCommandLine(text string) (string, bool) {
	text = strings.TrimSpace(text)
	if len(text) <= cmdlineLimit {
		return text, false
	}
	return text[:cmdlineLimit], true
}

func processState(stat string) (string, bool) {
	end := strings.LastIndex(stat, ")")
	if end < 0 || end+1 >= len(stat) {
		return "", false
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) == 0 || len(fields[0]) != 1 {
		return "", false
	}
	return fields[0], true
}

// ParseServiceList 解析 systemctl list-units 的纯文本输出。
// ParseServiceList parses the plain text produced by systemctl list-units.
//
// 每行至少四个字段，依次是单元名、加载状态、活动状态和子状态。描述被忽略。UNIT 表头被忽略。
// Each line has at least four fields: unit name, load state, active state, and sub state. The description is ignored. A UNIT header is ignored.
func ParseServiceList(text string) []map[string]any {
	var records []map[string]any
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] == "UNIT" {
			continue
		}
		records = append(records, map[string]any{"name": fields[0], "load": fields[1], "active": fields[2], "sub": fields[3]})
	}
	return records
}

// ParseDpkgStatus 读取 dpkg status 中状态为 installed 的软件包。
// ParseDpkgStatus reads packages whose status is installed from a dpkg status file.
//
// 只保留包名、版本和体系结构。Source 的第一个字段写入 source_package。配置文件残留和未安装记录不进入结果。
// Only the package name, version, and architecture are kept. The first field of Source is stored as source_package. Configuration-file remnants and records that are not installed are omitted.
func ParseDpkgStatus(text string) []map[string]any {
	var records []map[string]any
	for _, block := range strings.Split(text, "\n\n") {
		fields := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			if line == "" || line[0] == ' ' || line[0] == '\t' {
				continue
			}
			name, value, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			fields[name] = strings.TrimSpace(value)
		}
		status := strings.Fields(fields["Status"])
		if len(status) < 3 || status[2] != "installed" || fields["Package"] == "" || fields["Version"] == "" {
			continue
		}
		item := map[string]any{
			"name": fields["Package"], "version": fields["Version"], "architecture": fields["Architecture"], "source": "dpkg",
		}
		if source := sourcePackage(fields["Source"]); source != "" {
			item["source_package"] = source
		}
		records = append(records, item)
	}
	return records
}

// sourcePackage 取 dpkg Source 字段的包名。版本括号不进入包名。
// sourcePackage takes the package name from a dpkg Source field. A parenthesized version is not part of the name.
func sourcePackage(value string) string {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// ParseRPMQuery 解析 rpm 查询的五列文本：名称、纪元、版本、发布号、体系结构。
// ParseRPMQuery parses five-column rpm query text: name, epoch, version, release, and architecture.
//
// 空行被忽略。任一非空行不是五列，或名称、版本为空时返回错误。
// Blank lines are ignored. It returns an error when a non-blank line does not have five columns, or when the name or version is empty.
func ParseRPMQuery(text string) ([]map[string]any, error) {
	var records []map[string]any
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 5 || parts[0] == "" || parts[2] == "" {
			return nil, fmt.Errorf("parse rpm query: malformed line")
		}
		records = append(records, map[string]any{
			"name": parts[0], "epoch": parts[1], "version": parts[2], "release": parts[3], "architecture": parts[4], "source": "rpm",
		})
	}
	return records, nil
}

// BoundText 保留 text 的前 256 KiB。发生截断时 truncated 为 true。
// BoundText keeps the first 256 KiB of text. truncated is true when the text was cut.
func BoundText(text string) (string, bool) {
	if len(text) <= textLimit {
		return text, false
	}
	return text[:textLimit], true
}
