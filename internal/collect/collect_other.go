//go:build !linux && !windows

package collect

func collectPlatform(operation string) (Result, error) {
	return Result{Operation: operation, Status: StatusUnsupported}, nil
}
