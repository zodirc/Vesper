//go:build linux

package arpprobe

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"
)

// Availability 报告本进程能否打开 ARP 套接字，不发送报文。
// Availability reports whether this process can open an ARP socket. It sends no packet.
//
// 套接字打开成功时返回 available。权限不足时返回 permission_denied。其他失败返回 unavailable。
// It returns available when the socket opens. It returns permission_denied when permission is insufficient, and unavailable for every other failure.
func Availability() string {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(syscall.ETH_P_ARP)))
	if err != nil {
		if permissionDenied(err) {
			return "permission_denied"
		}
		return "unavailable"
	}
	_ = syscall.Close(fd)
	return "available"
}

func transmit(ctx context.Context, iface net.Interface, src, dst netip.Addr, timeout time.Duration, beforeSend func() error) (string, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(syscall.ETH_P_ARP)))
	if err != nil {
		if permissionDenied(err) {
			return "unsupported", nil
		}
		return "", err
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ARP), Ifindex: iface.Index}); err != nil {
		if permissionDenied(err) {
			return "unsupported", nil
		}
		return "", err
	}
	if beforeSend != nil {
		if err := beforeSend(); err != nil {
			return "", err
		}
	}
	if ctx.Err() != nil {
		return "not_attempted", nil
	}
	packet, err := Request(iface.HardwareAddr, src, dst)
	if err != nil {
		return "", err
	}
	destination := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ARP), Ifindex: iface.Index, Halen: 6,
		Addr: [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}
	if err := syscall.Sendto(fd, packet, 0, destination); err != nil {
		if permissionDenied(err) {
			return "unsupported", nil
		}
		if networkUnreachable(err) {
			return "unreachable", nil
		}
		return "", err
	}
	deadline := time.Now().Add(timeout)
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return "", err
	}
	buffer := make([]byte, 64)
	for {
		if !time.Now().Before(deadline) {
			return "no_response", nil
		}
		count, _, err := syscall.Recvfrom(fd, buffer, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.ETIMEDOUT) || isTimeout(err) {
				return "no_response", nil
			}
			return "", err
		}
		if ReplyMatches(buffer[:count], dst) {
			return "reachable", nil
		}
	}
}

func htons(value uint16) uint16 {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, value)
	return binary.NativeEndian.Uint16(buf)
}

func permissionDenied(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, os.ErrPermission)
}

func networkUnreachable(err error) bool {
	return errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETDOWN)
}

func isTimeout(err error) bool {
	var errno syscall.Errno
	return errors.As(err, &errno) && (errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK || errno == syscall.ETIMEDOUT)
}
