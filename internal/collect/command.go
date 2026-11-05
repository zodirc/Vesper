package collect

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

const commandTimeout = 15 * time.Second

func inventoryResult(operation string, records []map[string]any, key string, unreadable int) Result {
	status := StatusCollected
	if len(records) == 0 {
		status = StatusEmpty
	}
	if len(records) == 0 && unreadable > 0 {
		status = StatusPermissionDenied
	}
	value := map[string]any{key: records}
	if unreadable > 0 {
		value["unreadable"] = unreadable
	}
	return Result{Operation: operation, Status: status, Value: value}
}

func runCommand(operation, path string, args ...string) (string, Result, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return stdout.String(), Result{}, false
	}
	return "", commandFailure(operation, err, stderr.String()), true
}

func commandFailure(operation string, err error, stderr string) Result {
	text := strings.ToLower(stderr + " " + err.Error())
	if strings.Contains(text, "not been booted with systemd") || strings.Contains(text, "failed to connect to bus") {
		return Result{Operation: operation, Status: StatusUnsupported, Value: map[string]any{"error": "systemd is not available"}}
	}
	if strings.Contains(text, "permission denied") || strings.Contains(text, "operation not permitted") || strings.Contains(text, "access is denied") || strings.Contains(text, "requires elevation") {
		return Result{Operation: operation, Status: StatusPermissionDenied, Value: map[string]any{"error": "permission denied"}}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return Result{Operation: operation, Status: StatusError, Value: map[string]any{"error": "deadline exceeded"}}
	}
	message := strings.TrimSpace(stderr)
	if message == "" {
		message = err.Error()
	}
	if len(message) > 512 {
		message = message[:512]
	}
	return Result{Operation: operation, Status: StatusError, Value: map[string]any{"error": message}}
}
