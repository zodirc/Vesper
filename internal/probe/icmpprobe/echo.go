// Package icmpprobe 发送一条 ICMP Echo，并用应答判断可达性。
// Package icmpprobe sends one ICMP Echo and uses the reply to decide reachability.
package icmpprobe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Availability 报告本进程能否打开 ICMP Echo 套接字，不发送报文。
// Availability reports whether this process can open an ICMP Echo socket. It sends no packet.
//
// 套接字打开成功时返回 available。权限不足时返回 permission_denied。其他失败返回 unavailable。
// It returns available when the socket opens. It returns permission_denied when permission is insufficient, and unavailable for every other failure.
func Availability() string {
	conn, _, err := listen(netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		if permissionDenied(err) {
			return "permission_denied"
		}
		return "unavailable"
	}
	_ = conn.Close()
	return "available"
}

// Echo 向 ip 发送一条 Echo 请求。超时内没有匹配应答时返回 no_response。
// Echo sends one Echo request to ip. It returns no_response when no matching reply arrives within the timeout.
//
// 套接字无法打开时返回 unsupported，不把权限不足写成无响应。目的不可达或超时报文返回 unreachable。取消发生在发送前时不发送。
// It returns unsupported when the socket cannot be opened, and does not record insufficient permission as no response. A destination-unreachable or time-exceeded message returns unreachable. Cancellation before transmission sends nothing.
//
// timeout 必须大于 0。beforeSend 在套接字已经打开、请求尚未写出时调用；它返回错误时不发送。
// timeout must be greater than zero. beforeSend is called after the socket is open and before the request is written. Nothing is sent when it returns an error.
//
// 匹配的 Echo Reply 返回 reachable。标识或序号不同的应答会被忽略，直到超时返回 no_response。
// A matching Echo Reply returns reachable. A reply with a different identifier or sequence is ignored until the timeout returns no_response.
func Echo(ctx context.Context, ip netip.Addr, timeout time.Duration, beforeSend func() error) (string, error) {
	if timeout <= 0 {
		return "", fmt.Errorf("icmp echo: timeout is not configured")
	}
	if ctx.Err() != nil {
		return "not_attempted", nil
	}
	conn, identifier, err := listen(ip)
	if err != nil {
		if permissionDenied(err) {
			return "unsupported", nil
		}
		return "", err
	}
	defer conn.Close()
	if beforeSend != nil {
		if err := beforeSend(); err != nil {
			return "", err
		}
	}
	if ctx.Err() != nil {
		return "not_attempted", nil
	}
	return exchange(conn, ip, identifier, timeout)
}

func listen(ip netip.Addr) (*icmp.PacketConn, int, error) {
	networks := []string{"udp4", "ip4:icmp"}
	if ip.Is6() {
		networks = []string{"udp6", "ip6:ipv6-icmp"}
	}
	var last error
	for _, network := range networks {
		conn, err := icmp.ListenPacket(network, listenAddr(network))
		if err != nil {
			last = err
			continue
		}
		identifier := 1
		if udp, ok := conn.LocalAddr().(*net.UDPAddr); ok && udp.Port > 0 {
			identifier = udp.Port
		}
		return conn, identifier, nil
	}
	return nil, 0, last
}

func listenAddr(network string) string {
	switch network {
	case "udp4":
		return "0.0.0.0"
	case "udp6":
		return "::"
	default:
		return ""
	}
}

func exchange(conn *icmp.PacketConn, ip netip.Addr, identifier int, timeout time.Duration) (string, error) {
	message := icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &icmp.Echo{ID: identifier, Seq: 1, Data: []byte("vesper")}}
	protocol := 1
	if ip.Is6() {
		message.Type = ipv6.ICMPTypeEchoRequest
		protocol = 58
	}
	body, err := message.Marshal(nil)
	if err != nil {
		return "", err
	}
	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return "", err
	}
	if _, err := conn.WriteTo(body, destination(conn, ip)); err != nil {
		if permissionDenied(err) {
			return "unsupported", nil
		}
		if networkUnreachable(err) {
			return "unreachable", nil
		}
		if isTimeout(err) {
			return "no_response", nil
		}
		return "", err
	}
	buffer := make([]byte, 1500)
	for {
		count, _, err := conn.ReadFrom(buffer)
		if err != nil {
			if isTimeout(err) {
				return "no_response", nil
			}
			return "", err
		}
		switch classifyReply(ip, identifier, 1, protocol, buffer[:count]) {
		case "reachable":
			return "reachable", nil
		case "unreachable":
			return "unreachable", nil
		case "ignore":
			continue
		default:
			return "error", nil
		}
	}
}

func destination(conn *icmp.PacketConn, ip netip.Addr) net.Addr {
	if _, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return &net.UDPAddr{IP: ip.AsSlice()}
	}
	return &net.IPAddr{IP: ip.AsSlice()}
}

// ClassifyReply 判断一个 ICMP 报文是否匹配本次 Echo。
// ClassifyReply reports whether an ICMP message matches this Echo.
//
// reachable 表示标识和序号都匹配的 Echo Reply。unreachable 表示目的不可达或超时。ignore 表示报文属于其他请求。其他报文返回 error。
// reachable is an Echo Reply whose identifier and sequence match. unreachable is destination unreachable or time exceeded. ignore means the message belongs to another request. Any other message returns error.
func ClassifyReply(ip netip.Addr, identifier, sequence int, packet []byte) string {
	protocol := 1
	if ip.Is6() {
		protocol = 58
	}
	return classifyReply(ip, identifier, sequence, protocol, packet)
}

func classifyReply(ip netip.Addr, identifier, sequence, protocol int, packet []byte) string {
	message, err := icmp.ParseMessage(protocol, packet)
	if err != nil {
		return "error"
	}
	switch message.Type {
	case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
		body, ok := message.Body.(*icmp.Echo)
		if !ok || body.ID != identifier || body.Seq != sequence {
			return "ignore"
		}
		return "reachable"
	case ipv4.ICMPTypeDestinationUnreachable, ipv4.ICMPTypeTimeExceeded, ipv6.ICMPTypeDestinationUnreachable, ipv6.ICMPTypeTimeExceeded:
		return "unreachable"
	default:
		return "ignore"
	}
}

func permissionDenied(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, os.ErrPermission)
}

func networkUnreachable(err error) bool {
	return errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETDOWN)
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
