package collect

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// Socket 是一个处于监听状态的 TCP 套接字。
// Socket is a TCP socket in the listening state.
type Socket struct {
	Address   netip.Addr
	Port      int
	Transport string
}

// ParseProcNet 解析 /proc/net/tcp 或 /proc/net/tcp6 中的监听项。
// ParseProcNet parses listening entries from /proc/net/tcp or /proc/net/tcp6.
func ParseProcNet(reader io.Reader, transport string) ([]Socket, error) {
	scanner := bufio.NewScanner(reader)
	if !scanner.Scan() {
		return nil, fmt.Errorf("parse proc net: missing header")
	}
	var sockets []Socket
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		if fields[3] != "0A" {
			continue
		}
		addr, port, err := parseProcAddress(fields[1])
		if err != nil {
			return nil, err
		}
		sockets = append(sockets, Socket{Address: addr, Port: port, Transport: transport})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse proc net: %w", err)
	}
	return sockets, nil
}

func parseProcAddress(field string) (netip.Addr, int, error) {
	addrText, portText, ok := strings.Cut(field, ":")
	if !ok {
		return netip.Addr{}, 0, fmt.Errorf("parse proc address %q", field)
	}
	raw, err := hex.DecodeString(addrText)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("parse proc address %q: %w", field, err)
	}
	if len(raw) != 4 && len(raw) != 16 {
		return netip.Addr{}, 0, fmt.Errorf("parse proc address %q: invalid length", field)
	}
	for i := 0; i < len(raw); i += 4 {
		raw[i], raw[i+3] = raw[i+3], raw[i]
		raw[i+1], raw[i+2] = raw[i+2], raw[i+1]
	}
	addr, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.Addr{}, 0, fmt.Errorf("parse proc address %q", field)
	}
	port, err := strconv.ParseInt(portText, 16, 32)
	if err != nil || port < 1 || port > 65535 {
		return netip.Addr{}, 0, fmt.Errorf("parse proc port %q", portText)
	}
	return addr, int(port), nil
}
