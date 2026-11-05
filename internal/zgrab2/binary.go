// Package zgrab2 按固定模块调用操作者安装的 ZGrab2，不把扫描调度、授权或证据交给该程序。
// Package zgrab2 invokes an operator-installed ZGrab2 with a fixed module set. Scheduling, authorization, and evidence stay outside that program.
package zgrab2

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// ErrMissing 表示本机没有可执行的 ZGrab2。
// ErrMissing means this host has no runnable ZGrab2.
var ErrMissing = errors.New("zgrab2 is not installed")

// ErrRejected 表示标准输出不能作为这次授权目标的抓取结果。
// ErrRejected means standard output cannot be accepted as the grab for this authorized target.
var ErrRejected = errors.New("zgrab2 output rejected")

// Binary 返回操作者安装的 ZGrab2。VESPER_ZGRAB2 必须是绝对路径。没有设置时在 PATH 中查找。
// Binary returns the operator-installed ZGrab2. VESPER_ZGRAB2 must be an absolute path. Without it, PATH is searched.
//
// 程序不从网络下载。
// The program is not downloaded.
func Binary() (string, error) {
	if path := os.Getenv("VESPER_ZGRAB2"); path != "" {
		if !filepath.IsAbs(path) {
			return "", fmt.Errorf("%w: VESPER_ZGRAB2 is not absolute", ErrMissing)
		}
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			return "", fmt.Errorf("%w: %s", ErrMissing, path)
		}
		return path, nil
	}
	path, err := exec.LookPath("zgrab2")
	if err != nil {
		return "", ErrMissing
	}
	return path, nil
}
