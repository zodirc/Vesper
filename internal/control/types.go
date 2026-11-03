// Package control 按应用层协调目标、授权、任务、探测、识别和风险评估。
// Package control coordinates targets, authorization, tasks, probes, identification, and assessment at the application layer.
package control

import (
	"encoding/json"
	"time"

	"github.com/zodirc/Vesper/internal/id"
)

// Observation 是一条追加写入的观察事实。
// Observation is one append-only observation fact.
type Observation struct {
	ID                 id.ID
	ScanRunID          id.ID
	ScanUnitID         id.ID
	StageAttemptID     id.ID
	AssetID            id.ID
	EndpointID         *id.ID
	ObservationPointID id.ID
	Type               string
	SubjectKey         string
	ObservedAt         time.Time
	CollectedAt        time.Time
	ResultStatus       string
	ValueSchemaVersion string
	Value              map[string]any
	EvidenceIDs        []id.ID
	SourceKind         string
	SourceIdentity     string
	ContentDigest      string
}

// EvidenceRecord 是证据元数据。内容本身存放在证据目录，业务结果只引用已校验的记录。
// EvidenceRecord is evidence metadata. The content itself is stored in the evidence directory, and business results reference only verified records.
type EvidenceRecord struct {
	ID              id.ID
	EvidenceType    string
	StorageKey      string
	SizeBytes       int64
	DigestAlgorithm string
	ContentDigest   string
	ContentType     string
	ContentEncoding string
	SourceModule    string
	SourceAttemptID id.ID
	IntegrityStatus string
	Sensitivity     string
	CapturedAt      time.Time
	StoredAt        *time.Time
}

// Detection 是一条检测或适用性结果。
// Detection is one detection or applicability result.
type Detection struct {
	ID              id.ID
	AssessmentRunID id.ID
	EndpointID      id.ID
	SubjectType     string
	SubjectID       id.ID
	RuleID          id.ID
	RuleVersion     string
	VulnerabilityID string
	ResultStatus    string
	Severity        string
	Summary         string
	Matched         json.RawMessage
	Unmatched       json.RawMessage
	EvidenceIDs     []id.ID
	// InputObservationIDs 写入所属评估运行的输入集合，不保存在 detection_result。
	// InputObservationIDs is stored on the owning assessment run and is not a detection_result column.
	InputObservationIDs []id.ID
	// IntelSnapshotID 写入所属评估运行。检测结果表不保存这个快照标识。
	// IntelSnapshotID is stored on the owning assessment run. The detection result table does not store this snapshot identifier.
	IntelSnapshotID id.ID
	EvaluatedAt     time.Time
}

// Finding 是按稳定键归并的当前风险视图。
// Finding is the current risk view merged by a stable key.
type Finding struct {
	ID               id.ID
	FindingKey       string
	FindingType      string
	AssetID          id.ID
	EndpointID       id.ID
	ProductID        id.ID
	RuleID           id.ID
	VulnerabilityID  string
	Title            string
	Severity         string
	Status           string
	FirstSeenAt      time.Time
	LastSeenAt       time.Time
	LastOccurrenceID id.ID
}

// Occurrence 是一次风险出现，关闭风险时不删除。
// Occurrence is one risk occurrence and is not deleted when the risk is closed.
type Occurrence struct {
	ID              id.ID
	FindingID       id.ID
	AssessmentRunID id.ID
	DetectionID     id.ID
	ObservedAt      time.Time
	Severity        string
	EvidenceIDs     []id.ID
	ConditionDigest string
}

// Product 是规范产品身份。
// Product is a canonical product identity.
type Product struct {
	ID           id.ID
	Ecosystem    string
	ProductName  string
	CanonicalKey string
}

// Revision 是授权状态变更的审计记录。
// Revision is an audit record of an authorization status change.
type Revision struct {
	ID      id.ID
	GrantID id.ID
	Action  string
	ActorID id.ID
	Content json.RawMessage
	At      time.Time
}
