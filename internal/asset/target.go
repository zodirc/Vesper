// Package asset 维护扫描目标、临时端点和仅由稳定主机标识支撑的资产。
// Package asset maintains scan targets, temporary endpoints, and assets supported only by a stable host identifier.
//
// 相同 IP 不合并资产。没有机器标识时只保留端点，端点的 asset_id 为空。
// The same IP does not merge assets. Without a machine identifier only an endpoint is kept, and its asset_id stays empty.
package asset

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/scope"
)

// Target 是用户输入的扫描意图。
// Target is the scan intent supplied by the user.
type Target struct {
	ID              id.ID
	TargetType      string
	RawValue        string
	NormalizedValue string
	Address         *netip.Addr
	Prefix          *netip.Prefix
	Hostname        string
	Port            *int
	Transport       string
	CreatedAt       time.Time
}

// ParseTarget 按目标类型解析并保留原始输入。
// ParseTarget parses a target by type and preserves the raw input.
//
// targetType 取 ip、cidr、hostname、endpoint。endpoint 必须同时给出 1–65535 的端口和传输协议。
// targetType is ip, cidr, hostname, or endpoint. endpoint requires a port in 1–65535 and a transport.
func ParseTarget(targetType, raw, transport string, port *int, now time.Time) (Target, error) {
	target := Target{TargetType: targetType, RawValue: raw, Transport: transport, CreatedAt: now.UTC()}
	var err error
	target.ID, err = id.New()
	if err != nil {
		return Target{}, err
	}
	switch targetType {
	case "ip":
		addr, parseErr := netip.ParseAddr(raw)
		if parseErr != nil {
			return Target{}, fmt.Errorf("parse ip target: %w", parseErr)
		}
		addr = addr.Unmap()
		target.Address = &addr
		target.NormalizedValue = addr.String()
	case "cidr":
		prefix, parseErr := netip.ParsePrefix(raw)
		if parseErr != nil {
			return Target{}, fmt.Errorf("parse cidr target: %w", parseErr)
		}
		prefix = prefix.Masked()
		target.Prefix = &prefix
		target.NormalizedValue = prefix.String()
	case "hostname":
		host, parseErr := scope.NormalizeHostname(raw)
		if parseErr != nil {
			return Target{}, parseErr
		}
		target.Hostname = host
		target.NormalizedValue = host
	case "endpoint":
		addr, parseErr := netip.ParseAddr(raw)
		if parseErr != nil {
			return Target{}, fmt.Errorf("parse endpoint target: %w", parseErr)
		}
		if port == nil || *port < 1 || *port > 65535 || (transport != "tcp" && transport != "udp") {
			return Target{}, fmt.Errorf("parse endpoint target: port and transport are required")
		}
		addr = addr.Unmap()
		target.Address = &addr
		copied := *port
		target.Port = &copied
		target.NormalizedValue = fmt.Sprintf("%s/%s/%d", addr.String(), transport, copied)
	default:
		return Target{}, fmt.Errorf("parse target type %q: unsupported", targetType)
	}
	return target, nil
}

// Expand 把目标展开为本次计划要检查的地址。
// Expand expands a target into the addresses this plan will inspect.
//
// 地址数量超过 limit 时返回错误，不返回截断后的部分地址。hostname 不在这里解析。
// It returns an error when the address count exceeds limit and does not return a truncated address list. A hostname is not resolved here.
func Expand(target Target, limit int64) ([]netip.Addr, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("expand target: address limit must be positive")
	}
	switch target.TargetType {
	case "ip", "endpoint":
		if target.Address == nil {
			return nil, fmt.Errorf("expand target: missing address")
		}
		return []netip.Addr{*target.Address}, nil
	case "cidr":
		if target.Prefix == nil {
			return nil, fmt.Errorf("expand target: missing prefix")
		}
		return expandPrefix(*target.Prefix, limit)
	case "hostname":
		return nil, nil
	default:
		return nil, fmt.Errorf("expand target type %q: unsupported", target.TargetType)
	}
}

func expandPrefix(prefix netip.Prefix, limit int64) ([]netip.Addr, error) {
	prefix = prefix.Masked()
	hostBits := prefix.Addr().BitLen() - prefix.Bits()
	if hostBits >= 63 {
		return nil, fmt.Errorf("expand prefix %s: exceeds limit %d", prefix, limit)
	}
	size := uint64(1) << uint(hostBits)
	if size > uint64(limit) {
		return nil, fmt.Errorf("expand prefix %s: %d addresses exceed limit %d", prefix, size, limit)
	}
	out := make([]netip.Addr, 0, size)
	addr := prefix.Addr()
	for i := uint64(0); i < size; i++ {
		out = append(out, addr)
		next, ok := addrNext(addr)
		if !ok && i+1 < size {
			return nil, fmt.Errorf("expand prefix %s: address overflow", prefix)
		}
		addr = next
	}
	return out, nil
}

func addrNext(addr netip.Addr) (netip.Addr, bool) {
	raw := addr.AsSlice()
	for i := len(raw) - 1; i >= 0; i-- {
		raw[i]++
		if raw[i] != 0 {
			next, ok := netip.AddrFromSlice(raw)
			return next, ok
		}
	}
	return netip.Addr{}, false
}

// Endpoint 是地址、传输协议和端口组成的当前位置投影。
// Endpoint is the current projection of an address, transport, and port.
type Endpoint struct {
	ID              id.ID
	AssetID         *id.ID
	Address         netip.Addr
	Transport       string
	Port            int
	FirstObservedAt time.Time
	LastObservedAt  time.Time
	CurrentState    string
	StateObservedAt time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// Catalog 保存目标、端点投影和由机器标识建立的资产。
// Catalog stores targets, endpoint projections, and assets established from a machine identifier.
type Catalog struct {
	Targets   map[id.ID]Target
	Endpoints map[id.ID]Endpoint
	byKey     map[string]id.ID
	Assets    map[id.ID]Asset
	byMachine map[string]id.ID
}

// Asset 是由机器标识支撑的逻辑主机。
// Asset is a logical host supported by a machine identifier.
type Asset struct {
	ID                 id.ID
	AssetType          string
	PlatformFamily     string
	PlatformName       string
	PlatformVersion    string
	MachineIDHash      string
	IdentityConfidence string
	IdentityStatus     string
	FirstObservedAt    time.Time
	LastObservedAt     time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// Reset 用持久化副本重建目录索引。
// Reset rebuilds catalog indexes from a persisted copy.
func (c *Catalog) Reset(targets []Target, endpoints []Endpoint, assets []Asset) {
	c.Targets = map[id.ID]Target{}
	c.Endpoints = map[id.ID]Endpoint{}
	c.byKey = map[string]id.ID{}
	c.Assets = map[id.ID]Asset{}
	c.byMachine = map[string]id.ID{}
	for _, target := range targets {
		c.Targets[target.ID] = target
	}
	for _, endpoint := range endpoints {
		c.Endpoints[endpoint.ID] = endpoint
		c.byKey[fmt.Sprintf("%s|%s|%d", endpoint.Address.Unmap().String(), endpoint.Transport, endpoint.Port)] = endpoint.ID
	}
	for _, asset := range assets {
		c.Assets[asset.ID] = asset
		if asset.MachineIDHash != "" {
			c.byMachine[asset.MachineIDHash] = asset.ID
		}
	}
}

// NewCatalog 创建空目录。
// NewCatalog creates an empty catalog.
func NewCatalog() *Catalog {
	return &Catalog{
		Targets: map[id.ID]Target{}, Endpoints: map[id.ID]Endpoint{}, byKey: map[string]id.ID{},
		Assets: map[id.ID]Asset{}, byMachine: map[string]id.ID{},
	}
}

// AddTarget 保存扫描目标。
// AddTarget stores a scan target.
func (c *Catalog) AddTarget(target Target) {
	c.Targets[target.ID] = target
}

// ObserveEndpoint 按地址、传输协议和端口维护临时端点，并更新当前状态投影。
// ObserveEndpoint maintains a temporary endpoint by address, transport, and port, and updates the current state projection.
//
// 该方法不创建资产，也不因 IP 相同把端点绑定到已有资产。
// It does not create an asset and does not bind the endpoint to an existing asset because the IP is the same.
func (c *Catalog) ObserveEndpoint(addr netip.Addr, transport string, port int, state string, observedAt time.Time) Endpoint {
	observedAt = observedAt.UTC()
	key := fmt.Sprintf("%s|%s|%d", addr.Unmap().String(), transport, port)
	if existing, ok := c.byKey[key]; ok {
		item := c.Endpoints[existing]
		if !observedAt.Before(item.StateObservedAt) {
			item.CurrentState = state
			item.StateObservedAt = observedAt
			item.LastObservedAt = observedAt
			item.UpdatedAt = observedAt
			c.Endpoints[existing] = item
		}
		return c.Endpoints[existing]
	}
	item := Endpoint{
		ID: id.MustNew(), Address: addr.Unmap(), Transport: transport, Port: port,
		FirstObservedAt: observedAt, LastObservedAt: observedAt, CurrentState: state,
		StateObservedAt: observedAt, CreatedAt: observedAt, UpdatedAt: observedAt,
	}
	c.Endpoints[item.ID] = item
	c.byKey[key] = item.ID
	return item
}

// ObserveMachine 按机器标识摘要建立或更新资产。摘要为空时不创建资产。
// ObserveMachine creates or updates an asset from a machine-identifier digest. An empty digest does not create an asset.
func (c *Catalog) ObserveMachine(hash, family, name, version string, observedAt time.Time) (Asset, bool) {
	if hash == "" {
		return Asset{}, false
	}
	observedAt = observedAt.UTC()
	if existing, ok := c.byMachine[hash]; ok {
		item := c.Assets[existing]
		item.PlatformFamily = family
		item.PlatformName = name
		item.PlatformVersion = version
		item.LastObservedAt = observedAt
		item.UpdatedAt = observedAt
		c.Assets[existing] = item
		return item, true
	}
	item := Asset{
		ID: id.MustNew(), AssetType: "host", PlatformFamily: family, PlatformName: name, PlatformVersion: version,
		MachineIDHash: hash, IdentityConfidence: "0.8000", IdentityStatus: "candidate",
		FirstObservedAt: observedAt, LastObservedAt: observedAt, CreatedAt: observedAt, UpdatedAt: observedAt,
	}
	c.Assets[item.ID] = item
	c.byMachine[hash] = item.ID
	return item, true
}
