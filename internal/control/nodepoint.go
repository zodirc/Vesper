package control

import (
	"crypto/sha256"
	"encoding/json"
	"net"
	"runtime"
	"sort"
	"time"

	"github.com/zodirc/Vesper/internal/activedetect"
	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/probe/arpprobe"
	"github.com/zodirc/Vesper/internal/probe/icmpprobe"
	"github.com/zodirc/Vesper/internal/task"
)

var (
	icmpAvailability = icmpprobe.Availability
	arpAvailability  = arpprobe.Availability
)

// NetworkInterface 是观察点上的一块接口及其当前地址。
// NetworkInterface is one interface on an observation point and its current addresses.
type NetworkInterface struct {
	Name         string   `json:"name"`
	HardwareAddr string   `json:"hardware_addr,omitempty"`
	Addresses    []string `json:"addresses"`
	Up           bool     `json:"up"`
	Loopback     bool     `json:"loopback"`
}

// ObservationPoint 是本机观察点的当前环境。接口列表是环境快照，不是观察点身份。
// ObservationPoint is the current environment of the local observation point. The interface list is an environment snapshot, not the observation-point identity.
type ObservationPoint struct {
	ID                      id.ID
	NodeType                string
	Platform                string
	Architecture            string
	Interfaces              []NetworkInterface
	CapabilitySnapshotID    id.ID
	LocationLabel           string
	Capabilities            map[string]string
	Privileges              map[string]string
	NetworkIsolation        map[string]string
	ProbeCompatibility      map[string]string
	CapabilityCapturedAt    time.Time
	CapabilitySourceVersion string
}

// ObservationPointView 返回本机观察点。能力内容不变时快照标识保持不变。
// ObservationPointView returns the local observation point. The snapshot identifier stays unchanged while the capability content stays unchanged.
//
// 位置标签只返回已经保存的值。当前没有位置标签输入。主动检测隔离记录本次探测结果。
// The location label returns only a value that was already stored. There is no location-label input. Active-detection isolation records the current probe result.
func (s *Service) ObservationPointView() ObservationPoint {
	s.mu.Lock()
	worker := s.worker
	label := s.locationLabel
	pointID := s.pointID
	s.mu.Unlock()
	point := captureObservationPoint(pointID, worker, s.now())
	point.LocationLabel = label
	return point
}

func captureObservationPoint(pointID id.ID, worker task.Worker, now time.Time) ObservationPoint {
	names := make([]string, 0, len(worker.Capabilities))
	for name := range worker.Capabilities {
		names = append(names, name)
	}
	sort.Strings(names)
	capabilities := map[string]string{}
	compatibility := map[string]string{}
	for _, name := range names {
		capabilities[name] = "available"
		compatibility[name] = "available"
	}
	body := snapshotBody{
		Platform:           runtime.GOOS,
		Architecture:       runtime.GOARCH,
		Capabilities:       capabilities,
		Privileges:         map[string]string{"icmp_echo": icmpAvailability(), "arp": arpAvailability()},
		NetworkIsolation:   map[string]string{"active_detection": activedetect.Availability()},
		ProbeCompatibility: compatibility,
		SourceVersion:      "builtin-1",
	}
	canonical, err := json.Marshal(body)
	if err != nil {
		canonical = []byte("{}")
	}
	return ObservationPoint{
		ID: pointID, NodeType: "local_worker", Platform: body.Platform, Architecture: body.Architecture,
		Interfaces: localInterfaces(), CapabilitySnapshotID: snapshotID(canonical),
		Capabilities: body.Capabilities, Privileges: body.Privileges, NetworkIsolation: body.NetworkIsolation,
		ProbeCompatibility: body.ProbeCompatibility, CapabilityCapturedAt: now.UTC(), CapabilitySourceVersion: body.SourceVersion,
	}
}

type snapshotBody struct {
	Platform           string            `json:"platform"`
	Architecture       string            `json:"architecture"`
	Capabilities       map[string]string `json:"capabilities"`
	Privileges         map[string]string `json:"privileges"`
	NetworkIsolation   map[string]string `json:"network_isolation"`
	ProbeCompatibility map[string]string `json:"probe_compatibility"`
	SourceVersion      string            `json:"source_version"`
}

func snapshotID(canonical []byte) id.ID {
	sum := sha256.Sum256(canonical)
	var snapshot id.ID
	copy(snapshot[:], sum[:16])
	snapshot[6] = (snapshot[6] & 0x0f) | 0x50
	snapshot[8] = (snapshot[8] & 0x3f) | 0x80
	return snapshot
}

// observationEnvironment 是创建任务时冻结的观察点环境。
// observationEnvironment is the observation-point environment frozen when a task is created.
//
// 其中包含观察点标识、能力快照标识和当时的接口列表。后续保存观察点不改写已经创建的任务。
// It contains the observation-point identifier, the capability snapshot identifier, and the interface list at that time. A later observation-point save does not rewrite a task that was already created.
type observationEnvironment struct {
	ObservationPointID   string             `json:"observation_point_id"`
	CapabilitySnapshotID string             `json:"capability_snapshot_id"`
	Interfaces           []NetworkInterface `json:"network_interfaces"`
}

// currentEnvironment 读取本机观察点的当前环境。调用方不得持有 s.mu。
// currentEnvironment reads the current environment of the local observation point. The caller must not hold s.mu.
func (s *Service) currentEnvironment(now time.Time) observationEnvironment {
	s.mu.Lock()
	worker := s.worker
	pointID := s.pointID
	s.mu.Unlock()
	point := captureObservationPoint(pointID, worker, now)
	return observationEnvironment{
		ObservationPointID: pointID.String(), CapabilitySnapshotID: point.CapabilitySnapshotID.String(),
		Interfaces: append([]NetworkInterface(nil), point.Interfaces...),
	}
}

func localInterfaces() []NetworkInterface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return []NetworkInterface{}
	}
	var out []NetworkInterface
	for _, iface := range ifaces {
		item := NetworkInterface{Name: iface.Name, HardwareAddr: iface.HardwareAddr.String(), Addresses: []string{}, Up: iface.Flags&net.FlagUp != 0, Loopback: iface.Flags&net.FlagLoopback != 0}
		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				item.Addresses = append(item.Addresses, addr.String())
			}
			sort.Strings(item.Addresses)
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if out == nil {
		out = []NetworkInterface{}
	}
	return out
}
