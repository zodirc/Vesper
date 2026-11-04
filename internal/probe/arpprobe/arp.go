// Package arpprobe 在目标位于本机以太网网段时发送一条 ARP 请求。
// Package arpprobe sends one ARP request when the target is on a local Ethernet segment.
package arpprobe

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// Probe 向 ip 发送一条 ARP who-has。目标不是本机非回环网段上的 IPv4 地址时返回 not_attempted，不发送报文。
// Probe sends one ARP who-has to ip. It returns not_attempted and sends nothing when the target is not an IPv4 address on a local non-loopback segment.
//
// 套接字或接口不支持时返回 unsupported。匹配应答返回 reachable。超时返回 no_response。单一无响应不改写成离线。
// It returns unsupported when the socket or interface cannot perform ARP. A matching reply returns reachable. A timeout returns no_response. A single no-response is not rewritten as offline.
//
// timeout 必须大于 0。beforeSend 在套接字已经打开、请求尚未写出时调用；它返回错误时不发送。
// timeout must be greater than zero. beforeSend is called after the socket is open and before the request is written. Nothing is sent when it returns an error.
func Probe(ctx context.Context, ip netip.Addr, timeout time.Duration, beforeSend func() error) (string, error) {
	if timeout <= 0 {
		return "", fmt.Errorf("arp: timeout is not configured")
	}
	if ctx.Err() != nil {
		return "not_attempted", nil
	}
	iface, src, ok := OnLink(ip)
	if !ok {
		return "not_attempted", nil
	}
	return transmit(ctx, iface, src, ip, timeout, beforeSend)
}

// OnLink 报告 ip 是否落在一块已启用的非回环接口网段内，并返回该接口和接口地址。
// OnLink reports whether ip belongs to an enabled non-loopback interface prefix, and returns that interface and interface address.
func OnLink(ip netip.Addr) (net.Interface, netip.Addr, bool) {
	ifaces, err := net.Interfaces()
	if err != nil || !ip.Is4() || ip.IsLoopback() {
		return net.Interface{}, netip.Addr{}, false
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) != 6 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			src, prefix, ok := prefixFrom(ipNet)
			if ok && prefix.Contains(ip) {
				return iface, src, true
			}
		}
	}
	return net.Interface{}, netip.Addr{}, false
}

// SelectPrefix 在给定前缀中选择包含 ip 的非回环 IPv4 前缀。
// SelectPrefix chooses the non-loopback IPv4 prefix that contains ip.
func SelectPrefix(ip netip.Addr, prefixes []netip.Prefix) (netip.Prefix, bool) {
	if !ip.Is4() || ip.IsLoopback() {
		return netip.Prefix{}, false
	}
	for _, prefix := range prefixes {
		if !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Addr().IsLoopback() {
			continue
		}
		if prefix.Contains(ip) {
			return prefix, true
		}
	}
	return netip.Prefix{}, false
}

func prefixFrom(ipNet *net.IPNet) (netip.Addr, netip.Prefix, bool) {
	addr, ok := netip.AddrFromSlice(ipNet.IP)
	if !ok {
		return netip.Addr{}, netip.Prefix{}, false
	}
	addr = addr.Unmap()
	ones, bits := ipNet.Mask.Size()
	if bits != addr.BitLen() || ones < 0 {
		return netip.Addr{}, netip.Prefix{}, false
	}
	prefix, err := addr.Prefix(ones)
	if err != nil || !prefix.Addr().Is4() || prefix.Addr().IsLoopback() {
		return netip.Addr{}, netip.Prefix{}, false
	}
	return addr, prefix, true
}

// Request 构造一条以太网 ARP who-has。
// Request builds one Ethernet ARP who-has.
func Request(senderMAC net.HardwareAddr, sender, target netip.Addr) ([]byte, error) {
	if len(senderMAC) != 6 || !sender.Is4() || !target.Is4() {
		return nil, fmt.Errorf("arp request: address length is invalid")
	}
	packet := make([]byte, 28)
	binary.BigEndian.PutUint16(packet[0:2], 1)
	binary.BigEndian.PutUint16(packet[2:4], 0x0800)
	packet[4] = 6
	packet[5] = 4
	binary.BigEndian.PutUint16(packet[6:8], 1)
	senderIP := sender.As4()
	targetIP := target.As4()
	copy(packet[8:14], senderMAC)
	copy(packet[14:18], senderIP[:])
	copy(packet[24:28], targetIP[:])
	return packet, nil
}

// ReplyMatches 报告报文是否是目标地址发出的 ARP 应答。
// ReplyMatches reports whether the packet is an ARP reply sent by the target address.
func ReplyMatches(packet []byte, target netip.Addr) bool {
	if len(packet) < 28 || !target.Is4() {
		return false
	}
	if binary.BigEndian.Uint16(packet[0:2]) != 1 || binary.BigEndian.Uint16(packet[2:4]) != 0x0800 || packet[4] != 6 || packet[5] != 4 {
		return false
	}
	if binary.BigEndian.Uint16(packet[6:8]) != 2 {
		return false
	}
	var sender [4]byte
	copy(sender[:], packet[14:18])
	return netip.AddrFrom4(sender) == target
}
