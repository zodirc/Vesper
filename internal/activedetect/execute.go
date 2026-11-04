package activedetect

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const maxOutputBytes = 1 << 20

// Execute 在隔离环境里按固定参数运行已审核模板。隔离或执行器不存在时不创建进程。
// Execute runs reviewed templates with fixed arguments inside the isolated environment. It does not create a process when isolation or the executor is missing.
//
// 每个模板单独调用一次。标准输出最多读取 1 MiB。
// Each template is invoked once. Standard output is read up to 1 MiB.
func Execute(ctx context.Context, policy Policy, hostname string, ratePerSecond int, templates []Template) ([]byte, error) {
	if err := policy.validate(); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	binary, err := Binary()
	if err != nil {
		return nil, err
	}
	lease, err := openLease(ctx, policy)
	if err != nil {
		return nil, err
	}
	defer lease.Close()
	var output []byte
	for _, template := range templates {
		chunk, err := runOne(ctx, lease, binary, policy, hostname, ratePerSecond, template)
		output = append(output, chunk...)
		if err != nil {
			return output, err
		}
	}
	return output, nil
}

func runOne(ctx context.Context, lease Lease, binary string, policy Policy, hostname string, ratePerSecond int, template Template) ([]byte, error) {
	if template.Key == "" || len(template.Body) == 0 {
		return nil, fmt.Errorf("%w: template is empty", ErrNotStarted)
	}
	path := filepath.Join(lease.Dir(), template.Key+".yaml")
	if err := os.WriteFile(path, template.Body, 0o400); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotStarted, err)
	}
	args, err := CommandLine(binary, path, policy.AllowedIP, policy.AllowedPort, hostname, ratePerSecond)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotStarted, err)
	}
	cmd := lease.Command(ctx, args[0], args[1:])
	isolateProcess(cmd)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotStarted, err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return limited(stderr.Bytes()), fmt.Errorf("%w: %v", ErrNotStarted, err)
	}
	chunk, readErr := ReadLimited(stdout)
	waitErr := cmd.Wait()
	if readErr != nil {
		return chunk, fmt.Errorf("nuclei %s: %w", template.Key, readErr)
	}
	if waitErr != nil && !toleratedExit(waitErr, chunk) {
		detail := strings.TrimSpace(string(limited(stderr.Bytes())))
		if detail == "" {
			detail = waitErr.Error()
		}
		return chunk, fmt.Errorf("nuclei %s: %s", template.Key, detail)
	}
	return chunk, nil
}

func toleratedExit(err error, output []byte) bool {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 && len(output) > 0 {
		return true
	}
	return false
}

func limited(content []byte) []byte {
	if len(content) > maxOutputBytes {
		return append([]byte(nil), content[:maxOutputBytes]...)
	}
	return append([]byte(nil), content...)
}

// ReadLimited 读取最多 1 MiB，超出时返回错误。
// ReadLimited reads at most 1 MiB and returns an error when the input is longer.
func ReadLimited(reader io.Reader) ([]byte, error) {
	content, err := io.ReadAll(io.LimitReader(reader, maxOutputBytes+1))
	if err != nil {
		return nil, err
	}
	if len(content) > maxOutputBytes {
		return content[:maxOutputBytes], fmt.Errorf("nuclei output exceeds %d bytes", maxOutputBytes)
	}
	return content, nil
}
