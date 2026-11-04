//go:build !linux

package arpprobe

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// Availability 报告当前平台没有 ARP 套接字实现。
// Availability reports that the current platform has no ARP socket implementation.
func Availability() string {
	return "not_implemented"
}

func transmit(ctx context.Context, iface net.Interface, src, dst netip.Addr, timeout time.Duration, beforeSend func() error) (string, error) {
	return "unsupported", nil
}
