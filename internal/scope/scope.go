// Package scope 维护授权范围、受保护地址和执行预算。
// Package scope maintains authorization scope, protected addresses, and execution budgets.
//
// 授权判断只接受已经确定的 IP。主机名匹配不能代替最终连接地址的校验。
// Authorization decisions accept only a concrete IP. A hostname match does not replace the check of the final connected address.
package scope

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"golang.org/x/net/idna"

	"github.com/zodirc/Vesper/internal/id"
)

const (
	// StatusDraft 表示授权尚未生效。
	// StatusDraft means the grant is not yet effective.
	StatusDraft = "draft"
	// StatusActive 表示授权可以用于执行校验。
	// StatusActive means the grant can be used for execution checks.
	StatusActive = "active"
	// StatusRevoked 表示授权已被撤销。
	// StatusRevoked means the grant has been revoked.
	StatusRevoked = "revoked"
	// StatusExpired 表示授权已过有效期。
	// StatusExpired means the grant is past its validity window.
	StatusExpired = "expired"

	// OpDiscovery 是主机发现操作。
	// OpDiscovery is the host-discovery operation.
	OpDiscovery = "discovery"
	// OpConnect 是传输层连接操作。
	// OpConnect is the transport connection operation.
	OpConnect = "connect"
	// OpProtocolProbe 是有界协议探测操作。
	// OpProtocolProbe is the bounded protocol-probe operation.
	OpProtocolProbe = "protocol_probe"
	// OpConfigCheck 是配置检查操作。
	// OpConfigCheck is the configuration-check operation.
	OpConfigCheck = "config_check"
	// OpActiveCheck 是主动检测操作。
	// OpActiveCheck is the active-detection operation.
	OpActiveCheck = "active_check"
)

// Selector 是授权模块解析后的目标选择器。
// Selector is a target selector after the authorization module has parsed it.
type Selector struct {
	Kind     string       `json:"kind"`
	Value    string       `json:"value"`
	IP       netip.Addr   `json:"-"`
	Prefix   netip.Prefix `json:"-"`
	Hostname string       `json:"-"`
}

// PortRange 是闭区间端口范围。
// PortRange is an inclusive port interval.
type PortRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// Contains 报告端口是否落在闭区间内。
// Contains reports whether the port lies in the inclusive interval.
func (r PortRange) Contains(port int) bool {
	return port >= r.Start && port <= r.End
}

// Grant 是一次可执行授权的规范化数据。
// Grant is the normalized data of one executable authorization.
type Grant struct {
	ID                  id.ID
	Name                string
	SubjectType         string
	SubjectID           *id.ID
	Selectors           []Selector
	AllowedTransports   []string
	Ports               []PortRange
	AllowedOperations   []string
	ObservationPointIDs []id.ID
	ValidFrom           time.Time
	ValidUntil          *time.Time
	MaxTargets          int64
	MaxAddresses        int64
	MaxConnections      int64
	MaxRequests         int64
	MaxConcurrency      int
	MaxRatePerSecond    float64
	MaxRuntime          time.Duration
	MaxEvidenceBytes    int64
	Status              string
	ApprovedBy          *id.ID
	ApprovedAt          *time.Time
	RevokedAt           *time.Time
	RevocationReason    string
	CreatedAt           time.Time
}

// Decision 是一次授权判断的结果。
// Decision is the result of one authorization check.
type Decision struct {
	Allowed bool
	Code    string
}

// CheckInput 是对最终连接目标的校验输入。
// CheckInput is the check input for the final connection target.
type CheckInput struct {
	IP                 netip.Addr
	Hostname           string
	ResolvedFromGrant  bool
	Port               int
	Transport          string
	Operation          string
	ObservationPointID id.ID
	Now                time.Time
}

// ParseSelector 把外部选择器解析为可判定结构。
// ParseSelector parses an external selector into a structure that can be decided.
//
// kind 取 ip、cidr 或 hostname。value 是规范化前的文本。
// kind is ip, cidr, or hostname. value is the text before normalization.
//
// 无法解析时返回错误。hostname 按 IDNA2008 Lookup 转为 A-label 后再参与授权比较。
// It returns an error when the value cannot be parsed. Hostnames are converted to A-labels with IDNA2008 Lookup before authorization comparison.
func ParseSelector(kind, value string) (Selector, error) {
	switch kind {
	case "ip":
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return Selector{}, fmt.Errorf("parse ip selector %q: %w", value, err)
		}
		addr = addr.Unmap()
		return Selector{Kind: kind, Value: addr.String(), IP: addr}, nil
	case "cidr":
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return Selector{}, fmt.Errorf("parse cidr selector %q: %w", value, err)
		}
		prefix = prefix.Masked()
		return Selector{Kind: kind, Value: prefix.String(), Prefix: prefix}, nil
	case "hostname":
		host, err := NormalizeHostname(value)
		if err != nil {
			return Selector{}, err
		}
		return Selector{Kind: kind, Value: host, Hostname: host}, nil
	default:
		return Selector{}, fmt.Errorf("parse selector kind %q: unsupported", kind)
	}
}

// NormalizeHostname 把域名规范为用于匹配的 ASCII 形式。
// NormalizeHostname canonicalizes a hostname into the ASCII form used for matching.
//
// 去掉一个结尾的点后，使用 IDNA2008 Lookup 转为小写 A-label。Unicode 名称和对应的 punycode 得到同一结果。空名称、空标签和非法标签返回错误。
// After removing one trailing dot, IDNA2008 Lookup converts the name to a lowercase A-label. A Unicode name and its punycode produce the same result. Empty names, empty labels, and illegal labels return an error.
func NormalizeHostname(value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("normalize hostname: empty")
	}
	if value[len(value)-1] == '.' {
		value = value[:len(value)-1]
	}
	if value == "" {
		return "", fmt.Errorf("normalize hostname: empty")
	}
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil {
		return "", fmt.Errorf("normalize hostname %q: %w", value, err)
	}
	if ascii == "" {
		return "", fmt.Errorf("normalize hostname: empty")
	}
	return ascii, nil
}

// Check 判断输入是否可以被冻结后的授权允许。
// Check reports whether the input is permitted by the frozen grant.
//
// 受保护地址只有在选择器本身完全落在受保护空间内时才算明确授权。包含公网地址的宽范围选择器不能连带放行环回、链路本地或云元数据地址。
// A protected address is explicitly authorized only when the matching selector lies entirely inside protected space. A broad selector that also contains public addresses does not authorize loopback, link-local, or cloud-metadata addresses.
func (g Grant) Check(in CheckInput) Decision {
	if code := g.checkStatus(in.Now); code != "" {
		return Decision{Code: code}
	}
	if len(g.ObservationPointIDs) == 0 || !containsID(g.ObservationPointIDs, in.ObservationPointID) {
		return Decision{Code: "observation_point_denied"}
	}
	if in.Transport == "" || !slices.Contains(g.AllowedTransports, in.Transport) {
		return Decision{Code: "transport_denied"}
	}
	if in.Port < 1 || in.Port > 65535 || !portAllowed(g.Ports, in.Port) {
		return Decision{Code: "port_denied"}
	}
	if in.Operation == "" || !slices.Contains(g.AllowedOperations, in.Operation) {
		return Decision{Code: "operation_denied"}
	}
	if !in.IP.IsValid() {
		return Decision{Code: "address_not_in_scope"}
	}
	ip := in.IP.Unmap()
	if class := ProtectedClass(ip); class != "" {
		if !explicitProtected(g.Selectors, ip) {
			return Decision{Code: "protected_address"}
		}
		return Decision{Allowed: true}
	}
	if selectorContainsIP(g.Selectors, ip) {
		return Decision{Allowed: true}
	}
	if in.ResolvedFromGrant && hostnameAllowed(g.Selectors, in.Hostname) {
		return Decision{Allowed: true}
	}
	return Decision{Code: "address_not_in_scope"}
}

// CheckHostname 只判断域名是否被授权，不产生连接许可。
// CheckHostname reports only whether the hostname is authorized. It does not permit a connection.
func (g Grant) CheckHostname(host, transport, operation string, port int, point id.ID, now time.Time) Decision {
	if code := g.checkStatus(now); code != "" {
		return Decision{Code: code}
	}
	if len(g.ObservationPointIDs) == 0 || !containsID(g.ObservationPointIDs, point) {
		return Decision{Code: "observation_point_denied"}
	}
	if !slices.Contains(g.AllowedTransports, transport) {
		return Decision{Code: "transport_denied"}
	}
	if !portAllowed(g.Ports, port) {
		return Decision{Code: "port_denied"}
	}
	if !slices.Contains(g.AllowedOperations, operation) {
		return Decision{Code: "operation_denied"}
	}
	normalized, err := NormalizeHostname(host)
	if err != nil || !hostnameAllowed(g.Selectors, normalized) {
		return Decision{Code: "address_not_in_scope"}
	}
	return Decision{Allowed: true}
}

func (g Grant) checkStatus(now time.Time) string {
	now = now.UTC()
	switch g.Status {
	case StatusActive:
	case StatusRevoked:
		return "grant_revoked"
	case StatusExpired:
		return "grant_expired"
	default:
		return "grant_inactive"
	}
	if now.Before(g.ValidFrom.UTC()) {
		return "grant_not_yet_valid"
	}
	if g.ValidUntil != nil && !now.Before(g.ValidUntil.UTC()) {
		return "grant_expired"
	}
	return ""
}

// ProtectedClass 返回 loopback、link_local、metadata，普通地址返回空字符串。
// ProtectedClass returns loopback, link_local, or metadata. It returns an empty string for an ordinary address.
//
// 169.254.169.254 归类为 metadata。其余 IPv4 169.254.0.0/16 和 IPv6 fe80::/10 归类为 link_local。
// 169.254.169.254 is classified as metadata. The rest of IPv4 169.254.0.0/16 and IPv6 fe80::/10 are link_local.
func ProtectedClass(ip netip.Addr) string {
	ip = ip.Unmap()
	if ip == netip.MustParseAddr("169.254.169.254") {
		return "metadata"
	}
	if ip.IsLoopback() {
		return "loopback"
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return "link_local"
	}
	return ""
}

func explicitProtected(selectors []Selector, ip netip.Addr) bool {
	for _, sel := range selectors {
		switch sel.Kind {
		case "ip":
			if sel.IP.Unmap() == ip {
				return true
			}
		case "cidr":
			if sel.Prefix.Contains(ip) && prefixWithinProtected(sel.Prefix) {
				return true
			}
		}
	}
	return false
}

func prefixWithinProtected(prefix netip.Prefix) bool {
	prefix = prefix.Masked()
	first := prefix.Addr()
	last, ok := prefixLast(prefix)
	if !ok {
		return false
	}
	return ProtectedClass(first) != "" && ProtectedClass(last) != ""
}

func prefixLast(prefix netip.Prefix) (netip.Addr, bool) {
	addr := prefix.Addr()
	if !addr.Is4() && !addr.Is6() {
		return netip.Addr{}, false
	}
	raw := addr.AsSlice()
	hostBits := addr.BitLen() - prefix.Bits()
	for i := 0; i < hostBits; i++ {
		byteIndex := len(raw) - 1 - i/8
		raw[byteIndex] |= 1 << uint(i%8)
	}
	out, ok := netip.AddrFromSlice(raw)
	return out, ok
}

func selectorContainsIP(selectors []Selector, ip netip.Addr) bool {
	for _, sel := range selectors {
		switch sel.Kind {
		case "ip":
			if sel.IP.Unmap() == ip {
				return true
			}
		case "cidr":
			if sel.Prefix.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func hostnameAllowed(selectors []Selector, host string) bool {
	for _, sel := range selectors {
		if sel.Kind == "hostname" && sel.Hostname == host {
			return true
		}
	}
	return false
}

func portAllowed(ranges []PortRange, port int) bool {
	for _, r := range ranges {
		if r.Contains(port) {
			return true
		}
	}
	return false
}

func containsID(ids []id.ID, want id.ID) bool {
	return slices.Contains(ids, want)
}

// Digest 计算授权约束的 SHA-256 摘要，不包含可变状态字段。
// Digest computes the SHA-256 digest of the authorization constraints, excluding mutable status fields.
func (g Grant) Digest() (string, error) {
	payload := struct {
		ID                id.ID       `json:"id"`
		Selectors         []Selector  `json:"selectors"`
		Transports        []string    `json:"transports"`
		Ports             []PortRange `json:"ports"`
		Operations        []string    `json:"operations"`
		Points            []id.ID     `json:"points"`
		ValidFrom         time.Time   `json:"valid_from"`
		ValidUntil        *time.Time  `json:"valid_until,omitempty"`
		MaxTargets        int64       `json:"max_targets"`
		MaxAddresses      int64       `json:"max_addresses"`
		MaxConnections    int64       `json:"max_connections"`
		MaxRequests       int64       `json:"max_requests"`
		MaxConcurrency    int         `json:"max_concurrency"`
		MaxRatePerSecond  float64     `json:"max_rate_per_second"`
		MaxRuntimeSeconds int64       `json:"max_runtime_seconds"`
		MaxEvidenceBytes  int64       `json:"max_evidence_bytes"`
	}{
		ID: g.ID, Selectors: g.Selectors, Transports: g.AllowedTransports, Ports: g.Ports,
		Operations: g.AllowedOperations, Points: g.ObservationPointIDs, ValidFrom: g.ValidFrom.UTC(),
		ValidUntil: g.ValidUntil, MaxTargets: g.MaxTargets, MaxAddresses: g.MaxAddresses,
		MaxConnections: g.MaxConnections, MaxRequests: g.MaxRequests, MaxConcurrency: g.MaxConcurrency,
		MaxRatePerSecond: g.MaxRatePerSecond, MaxRuntimeSeconds: int64(g.MaxRuntime / time.Second),
		MaxEvidenceBytes: g.MaxEvidenceBytes,
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("digest grant: %w", err)
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:]), nil
}

// Budget 是授权、任务和探针共同收敛后的资源上限。
// Budget is the resource ceiling after narrowing the grant, task, and probe limits.
type Budget struct {
	MaxTargets       int64
	MaxAddresses     int64
	MaxConnections   int64
	MaxRequests      int64
	MaxConcurrency   int
	MaxRatePerSecond float64
	MaxRuntime       time.Duration
	MaxEvidenceBytes int64
}

// FromGrant 提取授权中的预算上限。
// FromGrant extracts the budget ceiling from a grant.
func FromGrant(g Grant) Budget {
	return Budget{
		MaxTargets: g.MaxTargets, MaxAddresses: g.MaxAddresses, MaxConnections: g.MaxConnections,
		MaxRequests: g.MaxRequests, MaxConcurrency: g.MaxConcurrency, MaxRatePerSecond: g.MaxRatePerSecond,
		MaxRuntime: g.MaxRuntime, MaxEvidenceBytes: g.MaxEvidenceBytes,
	}
}

// Narrow 取两个预算中每个维度更严格的上限。
// Narrow selects the stricter ceiling of each budget dimension.
func Narrow(a, b Budget) Budget {
	return Budget{
		MaxTargets:       min64(a.MaxTargets, b.MaxTargets),
		MaxAddresses:     min64(a.MaxAddresses, b.MaxAddresses),
		MaxConnections:   min64(a.MaxConnections, b.MaxConnections),
		MaxRequests:      min64(a.MaxRequests, b.MaxRequests),
		MaxConcurrency:   minInt(a.MaxConcurrency, b.MaxConcurrency),
		MaxRatePerSecond: minFloat(a.MaxRatePerSecond, b.MaxRatePerSecond),
		MaxRuntime:       minDuration(a.MaxRuntime, b.MaxRuntime),
		MaxEvidenceBytes: min64(a.MaxEvidenceBytes, b.MaxEvidenceBytes),
	}
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
