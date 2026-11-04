//go:build !linux

package activedetect

import (
	"context"
	"os"
)

func probeAvailability() string { return "not_verified" }

func openSystemLease(ctx context.Context, policy Policy) (Lease, error) {
	if err := policy.validate(); err != nil {
		return nil, err
	}
	return nil, ErrIsolation
}

// ProveNoEgress 在非 Linux 平台没有网络命名空间可证明。
// ProveNoEgress has no network namespace to prove on a non-Linux platform.
func ProveNoEgress() { os.Exit(2) }
