package activedetect

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"sync"
)

var (
	// ErrIsolation 表示操作系统级出口隔离没有被证明，执行器不应启动。
	// ErrIsolation means operating-system egress isolation was not proven and the executor must not start.
	ErrIsolation = errors.New("network isolation is not verified")
	// ErrExecutorMissing 表示本机没有 Nuclei 执行器。
	// ErrExecutorMissing means the Nuclei executor is not installed on this host.
	ErrExecutorMissing = errors.New("active detection executor is not installed")
	// ErrNotStarted 表示进程没有启动，已经占用的请求计数可以归还。
	// ErrNotStarted means the process did not start and a reserved request count can be returned.
	ErrNotStarted = errors.New("active detection process did not start")
)

// Policy 是一次执行允许到达的唯一目标。
// Policy is the only target one execution is allowed to reach.
type Policy struct {
	AllowedIP   netip.Addr
	AllowedPort int
}

func (p Policy) validate() error {
	if !p.AllowedIP.IsValid() || p.AllowedIP.IsUnspecified() || p.AllowedPort < 1 || p.AllowedPort > 65535 {
		return fmt.Errorf("isolation policy: target is invalid")
	}
	return nil
}

// Lease 是一次已经建立的隔离执行环境。
// Lease is one established isolated execution environment.
type Lease interface {
	Dir() string
	Command(ctx context.Context, binary string, args []string) *exec.Cmd
	Close() error
}

var (
	availabilityOnce  sync.Once
	availabilityValue = "not_verified"
	openLease         = openSystemLease
)

// Availability 返回主动检测隔离探测结果。available 表示空网络命名空间没有出口，并且可以为单一目标建立出站限制。
// Availability returns the active-detection isolation probe result. available means an empty network namespace has no egress and an outbound limit can be built for one target.
func Availability() string {
	availabilityOnce.Do(func() {
		availabilityValue = probeAvailability()
	})
	return availabilityValue
}

// Binary 返回操作者安装的 Nuclei 程序。VESPER_NUCLEI 必须是绝对路径。没有设置时在 PATH 中查找。
// Binary returns the operator-installed Nuclei program. VESPER_NUCLEI must be an absolute path. Without it, PATH is searched.
func Binary() (string, error) {
	if path := os.Getenv("VESPER_NUCLEI"); path != "" {
		if !isAbsolute(path) {
			return "", fmt.Errorf("%w: VESPER_NUCLEI is not absolute", ErrExecutorMissing)
		}
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			return "", fmt.Errorf("%w: %s", ErrExecutorMissing, path)
		}
		return path, nil
	}
	path, err := exec.LookPath("nuclei")
	if err != nil {
		return "", ErrExecutorMissing
	}
	return path, nil
}

func isAbsolute(path string) bool {
	return len(path) > 0 && path[0] == '/'
}
