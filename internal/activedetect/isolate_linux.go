package activedetect

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func probeAvailability() string {
	if os.Geteuid() != 0 || !forwardingEnabled() || !toolsPresent() {
		return "not_verified"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := proveEmptyNamespace(ctx); err != nil {
		return "not_verified"
	}
	lease, err := buildLease(ctx, Policy{AllowedIP: netip.MustParseAddr("192.0.2.1"), AllowedPort: 9})
	if err != nil {
		return "not_verified"
	}
	defer lease.Close()
	if err := provePolicy(ctx, lease); err != nil {
		return "not_verified"
	}
	return "available"
}

func openSystemLease(ctx context.Context, policy Policy) (Lease, error) {
	if err := policy.validate(); err != nil {
		return nil, err
	}
	if Availability() != "available" {
		return nil, ErrIsolation
	}
	return buildLease(ctx, policy)
}

func proveEmptyNamespace(ctx context.Context) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if filepath.Base(exe) != "vesperd" {
		return fmt.Errorf("isolation helper is not vesperd")
	}
	cmd := exec.CommandContext(ctx, exe)
	cmd.Env = []string{"VESPER_ISOLATE_PROVE=1", "PATH=" + os.Getenv("PATH")}
	return cmd.Run()
}

// ProveNoEgress 在新的网络命名空间里确认没有出口。供 vesperd 在隔离探测子进程中调用。
// ProveNoEgress confirms that a new network namespace has no egress. vesperd calls it in the isolation-probe child.
func ProveNoEgress() {
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		os.Exit(2)
	}
	dialer := net.Dialer{Timeout: 200 * time.Millisecond}
	conn, err := dialer.Dial("tcp", "192.0.2.1:9")
	if err == nil {
		_ = conn.Close()
		os.Exit(1)
	}
	os.Exit(0)
}

func forwardingEnabled() bool {
	raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	return err == nil && strings.TrimSpace(string(raw)) == "1"
}

func toolsPresent() bool {
	_, ipErr := exec.LookPath("ip")
	_, nftErr := exec.LookPath("nft")
	return ipErr == nil && nftErr == nil
}

type namespaceLease struct {
	dir     string
	name    string
	host    string
	peer    string
	suffix  string
	gateway netip.Addr
	cleanup []func()
}

func (l *namespaceLease) Dir() string { return l.dir }

func (l *namespaceLease) Command(ctx context.Context, binary string, args []string) *exec.Cmd {
	wrapped := append([]string{"netns", "exec", l.name, "--", binary}, args...)
	cmd := exec.CommandContext(ctx, "ip", wrapped...)
	cmd.Dir = l.dir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + l.dir,
		"NUCLEI_DISABLE_UPDATE_CHECK=true",
		"HTTP_PROXY=", "HTTPS_PROXY=", "http_proxy=", "https_proxy=", "NO_PROXY=*",
	}
	return cmd
}

func (l *namespaceLease) Close() error {
	for i := len(l.cleanup) - 1; i >= 0; i-- {
		l.cleanup[i]()
	}
	return os.RemoveAll(l.dir)
}

func buildLease(ctx context.Context, policy Policy) (*namespaceLease, error) {
	if err := policy.validate(); err != nil {
		return nil, err
	}
	suffix, err := randomSuffix()
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "vesper-active-")
	if err != nil {
		return nil, err
	}
	gateway := netip.MustParseAddr("172.31.255.1")
	inside := netip.MustParseAddr("172.31.255.2")
	if policy.AllowedIP.Compare(gateway) == 0 || policy.AllowedIP.Compare(inside) == 0 {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("isolation policy: target overlaps the namespace link")
	}
	lease := &namespaceLease{
		dir: dir, name: "vesper" + suffix, host: "vh" + suffix[:6], peer: "vp" + suffix[:6],
		suffix: suffix, gateway: gateway,
	}
	fail := func(err error) (*namespaceLease, error) {
		_ = lease.Close()
		return nil, err
	}
	if err := runCommand(ctx, "ip", "netns", "add", lease.name); err != nil {
		return fail(err)
	}
	lease.cleanup = append(lease.cleanup, func() { _ = runCommand(context.Background(), "ip", "netns", "del", lease.name) })
	if err := runCommand(ctx, "ip", "link", "add", lease.host, "type", "veth", "peer", "name", lease.peer); err != nil {
		return fail(err)
	}
	lease.cleanup = append(lease.cleanup, func() { _ = runCommand(context.Background(), "ip", "link", "del", lease.host) })
	if err := runCommand(ctx, "ip", "link", "set", lease.peer, "netns", lease.name); err != nil {
		return fail(err)
	}
	if err := runCommand(ctx, "ip", "addr", "add", gateway.String()+"/30", "dev", lease.host); err != nil {
		return fail(err)
	}
	if err := runCommand(ctx, "ip", "link", "set", lease.host, "up"); err != nil {
		return fail(err)
	}
	if err := runCommand(ctx, "ip", "netns", "exec", lease.name, "ip", "addr", "add", inside.String()+"/30", "dev", lease.peer); err != nil {
		return fail(err)
	}
	if err := runCommand(ctx, "ip", "netns", "exec", lease.name, "ip", "link", "set", "lo", "up"); err != nil {
		return fail(err)
	}
	if err := runCommand(ctx, "ip", "netns", "exec", lease.name, "ip", "link", "set", lease.peer, "up"); err != nil {
		return fail(err)
	}
	if err := runCommand(ctx, "ip", "netns", "exec", lease.name, "ip", "route", "add", "default", "via", gateway.String()); err != nil {
		return fail(err)
	}
	if err := applyRules(ctx, lease.name, namespaceOutputRuleset(lease.suffix, policy)); err != nil {
		return fail(err)
	}
	if err := applyRules(ctx, "", hostRuleset(lease.suffix, policy, inside)); err != nil {
		return fail(err)
	}
	lease.cleanup = append(lease.cleanup, func() { _ = deleteRules(lease.name, lease.suffix) })
	return lease, nil
}

func provePolicy(ctx context.Context, lease *namespaceLease) error {
	if err := runCommand(ctx, "ip", "netns", "exec", lease.name, "ip", "route", "get", "192.0.2.1"); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", lease.name, "nft", "list", "ruleset")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}
	if !strings.Contains(string(out), "policy drop") || !strings.Contains(string(out), "192.0.2.1") {
		return fmt.Errorf("isolation ruleset does not name the allowed target")
	}
	return nil
}

func namespaceOutputRuleset(suffix string, policy Policy) string {
	return fmt.Sprintf(`table inet vesperout%s {
	chain output {
		type filter hook output priority 0; policy drop;
		ct state established,related accept
		ip daddr %s tcp dport %d accept
		ip daddr %s ip protocol icmp accept
	}
}
`, suffix, policy.AllowedIP, policy.AllowedPort, policy.AllowedIP)
}

func hostRuleset(suffix string, policy Policy, source netip.Addr) string {
	return fmt.Sprintf(`table ip vespernat%s {
	chain postrouting {
		type nat hook postrouting priority 100; policy accept;
		ip saddr %s masquerade
	}
}
table ip vesperfwd%s {
	chain forward {
		type filter hook forward priority -10; policy accept;
		ip saddr %s ip daddr %s tcp dport %d accept
		ip daddr %s ct state established,related accept
		ip saddr %s drop
	}
}
`, suffix, source, suffix, source, policy.AllowedIP, policy.AllowedPort, source, source)
}

func applyRules(ctx context.Context, namespace, rules string) error {
	var cmd *exec.Cmd
	if namespace == "" {
		cmd = exec.CommandContext(ctx, "nft", "-f", "-")
	} else {
		cmd = exec.CommandContext(ctx, "ip", "netns", "exec", namespace, "nft", "-f", "-")
	}
	cmd.Stdin = strings.NewReader(rules)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %w: %s", err, truncate(out))
	}
	return nil
}

func deleteRules(namespace, suffix string) error {
	_ = runCommand(context.Background(), "ip", "netns", "exec", namespace, "nft", "delete", "table", "inet", "vesperout"+suffix)
	_ = runCommand(context.Background(), "nft", "delete", "table", "ip", "vespernat"+suffix)
	_ = runCommand(context.Background(), "nft", "delete", "table", "ip", "vesperfwd"+suffix)
	return nil
}

func runCommand(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, truncate(out))
	}
	return nil
}

func randomSuffix() (string, error) {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func truncate(content []byte) string {
	if len(content) > 180 {
		return string(content[:180])
	}
	return string(content)
}
