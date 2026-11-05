package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/zodirc/Vesper/internal/assess"
	"github.com/zodirc/Vesper/internal/asset"
	"github.com/zodirc/Vesper/internal/evidence"
	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/identity"
	"github.com/zodirc/Vesper/internal/rule"
	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/internal/task"
)

// Resolution 是解析器实际返回的数据。标准库不提供 TTL 和逐跳 CNAME 链，因此这里不包含这两项。
// Resolution is the data the resolver actually returned. The standard library does not provide TTL or the per-hop CNAME chain, so neither is included.
type Resolution struct {
	CanonicalName  string
	CanonicalError string
	Addresses      []netip.Addr
}

// Resolver 解析域名。解析结果本身不是连接许可。
// Resolver resolves a hostname. A resolution result is not permission to connect.
type Resolver func(ctx context.Context, host string) (Resolution, error)

// GrantInput 是创建授权所需的外部输入。
// GrantInput is the external input required to create a grant.
type GrantInput struct {
	Name                string            `json:"name"`
	SubjectType         string            `json:"subject_type"`
	Selectors           []SelectorInput   `json:"target_selectors"`
	Transports          []string          `json:"allowed_transports"`
	Ports               []scope.PortRange `json:"allowed_ports"`
	Operations          []string          `json:"allowed_operations"`
	ObservationPointIDs []id.ID           `json:"observation_point_ids"`
	ValidFrom           time.Time         `json:"valid_from"`
	ValidUntil          *time.Time        `json:"valid_until,omitempty"`
	MaxTargets          int64             `json:"max_targets"`
	MaxAddresses        int64             `json:"max_addresses"`
	MaxConnections      int64             `json:"max_connections"`
	MaxRequests         int64             `json:"max_requests"`
	MaxConcurrency      int               `json:"max_concurrency"`
	MaxRatePerSecond    float64           `json:"max_rate_per_second"`
	MaxRuntimeSeconds   int64             `json:"max_runtime_seconds"`
	MaxEvidenceBytes    int64             `json:"max_evidence_bytes"`
}

// SelectorInput 是授权目标选择器的外部表示。
// SelectorInput is the external form of an authorization target selector.
type SelectorInput struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// ScanInput 是创建一次扫描运行的输入。
// ScanInput is the input for creating one scan run.
type ScanInput struct {
	Name      string `json:"name"`
	Target    string `json:"target"`
	Type      string `json:"type"`
	Port      *int   `json:"port,omitempty"`
	Transport string `json:"transport,omitempty"`
	Ports     []int  `json:"ports"`
	GrantID   id.ID  `json:"grant_id"`
}

// Service 协调单机扫描闭环。
// Service coordinates the single-node scan loop.
type Service struct {
	mu            sync.Mutex
	now           func() time.Time
	tasks         *task.Engine
	catalog       *asset.Catalog
	evidence      evidence.Store
	worker        task.Worker
	pointID       id.ID
	principal     id.ID
	grants        map[id.ID]scope.Grant
	frozen        map[id.ID]scope.Grant
	accounts      map[id.ID]*scope.Account
	baselines     map[id.ID]scope.Usage
	observations  []Observation
	idempotency   map[string]id.ID
	evidenceRows  []EvidenceRecord
	hypotheses    []identity.Hypothesis
	products      map[id.ID]Product
	aliases       []identity.Alias
	statements    []assess.Statement
	snapshots     []IntelSnapshot
	detections    []Detection
	findings      map[string]*Finding
	occurrences   []Occurrence
	dispositions  []Disposition
	revisions     []Revision
	resolver      Resolver
	DialTimeout   time.Duration
	locationLabel string
	db            *pgStore
	packs         []rule.Pack
	active        []activeTemplate
	schedules     map[id.ID]Schedule
	firing        map[id.ID]struct{}
	feeds         map[string]FeedStatus
	feedClient    *http.Client
	nvdFeedURL    string
	kevFeedURL    string
	epssFeedURL   string
}

// New 创建本机观察点、在线 Worker 和应用服务。
// New creates the local observation point, the online worker, and the application service.
//
// evidenceRoot 是证据文件目录。now 为空时使用当前 UTC 时间。
// evidenceRoot is the evidence file directory. When now is nil, the current UTC time is used.
func New(evidenceRoot string, now func() time.Time) (*Service, error) {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	packs, err := rule.Builtin(now())
	if err != nil {
		return nil, err
	}
	pointID, err := id.New()
	if err != nil {
		return nil, err
	}
	workerID, err := id.New()
	if err != nil {
		return nil, err
	}
	principal, err := id.New()
	if err != nil {
		return nil, err
	}
	return &Service{
		now: now, tasks: task.NewEngine(30 * time.Second), catalog: asset.NewCatalog(),
		evidence: evidence.Store{Root: evidenceRoot}, pointID: pointID, principal: principal,
		worker: task.Worker{ID: workerID, ObservationPointID: pointID, Status: "online", Capabilities: localCapabilities()},
		grants: map[id.ID]scope.Grant{}, frozen: map[id.ID]scope.Grant{}, accounts: map[id.ID]*scope.Account{},
		baselines:   map[id.ID]scope.Usage{},
		idempotency: map[string]id.ID{}, products: map[id.ID]Product{}, findings: map[string]*Finding{}, active: []activeTemplate{},
		schedules: map[id.ID]Schedule{}, firing: map[id.ID]struct{}{}, feeds: map[string]FeedStatus{},
		resolver: defaultResolver, DialTimeout: 2 * time.Second, packs: packs,
	}, nil
}

// Open 连接 PostgreSQL，执行迁移，并恢复本机观察点、任务和结果。
// Open connects to PostgreSQL, applies migrations, and restores the local observation point, tasks, and results.
//
// 恢复后的任务状态来自已提交的数据行。调用方需要使用同一个证据目录，证据文件才能和元数据对上。
// Restored task state comes from committed rows. The caller must use the same evidence directory for metadata to match the files.
func Open(ctx context.Context, evidenceRoot, dsn, migrationFile string, now func() time.Time) (*Service, error) {
	store, err := openStore(ctx, dsn, migrationFile)
	if err != nil {
		return nil, err
	}
	service, err := New(evidenceRoot, now)
	if err != nil {
		store.pool.Close()
		return nil, err
	}
	service.db = store
	if err := store.load(ctx, service); err != nil {
		store.pool.Close()
		return nil, err
	}
	principal, err := store.ensurePrincipal(ctx, service.principal)
	if err != nil {
		store.pool.Close()
		return nil, err
	}
	service.principal = principal
	if err := service.reconcileEvidence(ctx); err != nil {
		store.pool.Close()
		return nil, err
	}
	return service, nil
}

// Close 关闭数据库连接。已经写入的任务状态保留在 PostgreSQL 中。
// Close closes the database connection. Task state that was committed remains in PostgreSQL.
func (s *Service) Close() {
	if s.db != nil {
		s.db.pool.Close()
	}
}

// localCapabilities 是当前构建能够执行的探针和采集能力。
// localCapabilities is the set of probe and collection capabilities this build can execute.
//
// 已保存的本机 Worker 在装入时补齐这里缺少的名称。已创建扫描写入的能力快照不改写。udp_dns 覆盖已注册的 UDP 探针，目前是 DNS 和 NTP。
// A stored local worker gains any name missing from this set when it is loaded. Capability snapshots already written for a scan stay unchanged. udp_dns covers the registered UDP probes, currently DNS and NTP.
func localCapabilities() map[string]struct{} {
	names := []string{
		"tcp_connect", "protocol_http", "protocol_tls", "protocol_ssh", "protocol_ftp", "protocol_smtp",
		"protocol_mysql", "protocol_postgresql", "protocol_redis", "protocol_mongodb", "protocol_tds", "protocol_tns",
		"protocol_cql", "protocol_bolt", "protocol_memcached", "protocol_clickhouse",
		"protocol_telnet", "protocol_pop3", "protocol_imap", "protocol_vnc", "protocol_nats", "protocol_rdp",
		"protocol_amqp", "protocol_mqtt", "protocol_kafka",
		"udp_dns", "host_collect", "active_detection", "zgrab2",
	}
	out := make(map[string]struct{}, len(names))
	for _, name := range names {
		out[name] = struct{}{}
	}
	return out
}

// ObservationPointID 返回本机观察点标识。
// ObservationPointID returns the local observation point identifier.
func (s *Service) ObservationPointID() id.ID {
	return s.pointID
}

// CreateGrant 登记一条 draft 授权，并写入审计记录。
// CreateGrant records one draft grant and writes an audit record.
func (s *Service) CreateGrant(input GrantInput, actor id.ID) (scope.Grant, error) {
	if input.Name == "" || input.SubjectType == "" || len(input.Selectors) == 0 || len(input.Transports) == 0 || len(input.Ports) == 0 || len(input.Operations) == 0 || len(input.ObservationPointIDs) == 0 {
		return scope.Grant{}, fmt.Errorf("create grant: required scope fields are empty")
	}
	if input.MaxTargets <= 0 || input.MaxAddresses <= 0 || input.MaxConnections <= 0 || input.MaxRequests <= 0 || input.MaxConcurrency <= 0 || input.MaxRatePerSecond <= 0 || input.MaxRuntimeSeconds <= 0 || input.MaxEvidenceBytes <= 0 {
		return scope.Grant{}, fmt.Errorf("create grant: budget ceilings must be positive")
	}
	var selectors []scope.Selector
	for _, item := range input.Selectors {
		parsed, err := scope.ParseSelector(item.Kind, item.Value)
		if err != nil {
			return scope.Grant{}, err
		}
		selectors = append(selectors, parsed)
	}
	grantID, err := id.New()
	if err != nil {
		return scope.Grant{}, err
	}
	grant := scope.Grant{
		ID: grantID, Name: input.Name, SubjectType: input.SubjectType, Selectors: selectors,
		AllowedTransports: input.Transports, Ports: input.Ports, AllowedOperations: input.Operations,
		ObservationPointIDs: input.ObservationPointIDs, ValidFrom: input.ValidFrom.UTC(), ValidUntil: input.ValidUntil,
		MaxTargets: input.MaxTargets, MaxAddresses: input.MaxAddresses, MaxConnections: input.MaxConnections,
		MaxRequests: input.MaxRequests, MaxConcurrency: input.MaxConcurrency, MaxRatePerSecond: input.MaxRatePerSecond,
		MaxRuntime: time.Duration(input.MaxRuntimeSeconds) * time.Second, MaxEvidenceBytes: input.MaxEvidenceBytes, Status: scope.StatusDraft, CreatedAt: s.now().UTC(),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.commitState(context.Background(), func() error {
		s.grants[grant.ID] = grant
		return s.audit(grant.ID, "draft", actor)
	}); err != nil {
		return scope.Grant{}, err
	}
	return grant, nil
}

// ApproveGrant 把 draft 授权转为 active。
// ApproveGrant turns a draft grant into active.
func (s *Service) ApproveGrant(grantID, actor id.ID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commitState(context.Background(), func() error {
		grant, ok := s.grants[grantID]
		if !ok {
			return fmt.Errorf("approve grant: not found")
		}
		if grant.Status != scope.StatusDraft {
			return fmt.Errorf("approve grant: status %s", grant.Status)
		}
		now := s.now().UTC()
		grant.Status = scope.StatusActive
		grant.ApprovedBy = &actor
		grant.ApprovedAt = &now
		s.grants[grantID] = grant
		return s.audit(grantID, "approve", actor)
	})
}

// RevokeGrant 撤销授权。正在使用该授权的后续连接会被拒绝。
// RevokeGrant revokes a grant. Later connections that use it are denied.
//
// grantID 必须是已存在的授权。actor 是执行撤销的用户。reason 不能为空。
// grantID must be an existing grant. actor is the user performing the revocation. reason must not be empty.
//
// 授权不存在或原因为空时返回错误。已经撤销的授权会再写一条撤销审计。
// It returns an error when the grant does not exist or the reason is empty. An already revoked grant receives another revocation audit record.
func (s *Service) RevokeGrant(grantID, actor id.ID, reason string) error {
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("revoke grant: reason is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commitState(context.Background(), func() error {
		grant, ok := s.grants[grantID]
		if !ok {
			return fmt.Errorf("revoke grant: not found")
		}
		now := s.now().UTC()
		grant.Status = scope.StatusRevoked
		grant.RevokedAt = &now
		grant.RevocationReason = reason
		s.grants[grantID] = grant
		return s.audit(grantID, "revoke", actor)
	})
}

// Grant 返回授权副本。
// Grant returns a copy of one grant.
//
// grantID 不存在时返回错误。
// It returns an error when grantID does not exist.
func (s *Service) Grant(grantID id.ID) (scope.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	grant, ok := s.grants[grantID]
	if !ok {
		return scope.Grant{}, fmt.Errorf("grant %s: not found", grantID)
	}
	return copyGrant(grant), nil
}

// Revisions 返回某条授权的审计记录副本，顺序与写入顺序一致。
// Revisions returns copies of one grant's audit records in write order.
func (s *Service) Revisions(grantID id.ID) []Revision {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Revision
	for _, item := range s.revisions {
		if item.GrantID != grantID {
			continue
		}
		item.Content = append(json.RawMessage(nil), item.Content...)
		out = append(out, item)
	}
	return out
}

// expireGrants 把已过 valid_until 的 active 授权标为 expired，并写入审计。
// expireGrants marks active grants past valid_until as expired and writes an audit record.
//
// 操作者是本机 Worker。这是控制进程根据有效期作出的状态迁移，不是用户撤销。
// The actor is the local worker. This is the control process applying the validity window, not a user revocation.
func (s *Service) expireGrants() error {
	now := s.now().UTC()
	for grantID, grant := range s.grants {
		if grant.Status != scope.StatusActive || grant.ValidUntil == nil || now.Before(grant.ValidUntil.UTC()) {
			continue
		}
		grant.Status = scope.StatusExpired
		s.grants[grantID] = grant
		if err := s.audit(grantID, "expire", s.worker.ID); err != nil {
			return err
		}
	}
	return nil
}

// AddProduct 登记一个产品和一条产品名别名。厂商、产品系列、CPE 和 PURL 留空。
// AddProduct records one product and one product-name alias. Vendor, product family, CPE, and PURL stay empty.
func (s *Service) AddProduct(ecosystem, name, canonicalKey, aliasValue string) (Product, error) {
	return s.AddProductIdentity(Product{Ecosystem: ecosystem, ProductName: name, CanonicalKey: canonicalKey}, []identity.Alias{{
		Source: "catalog", AliasType: "product_name", Value: aliasValue,
	}})
}

// AddStatement 登记一条本地漏洞情报，并在内容变化时发布新的情报快照。KEV 只作为语句属性保存。
// AddStatement records one local vulnerability statement and publishes a new intelligence snapshot when the content changed. KEV is stored only as a statement attribute.
func (s *Service) AddStatement(statement assess.Statement) error {
	prepared, err := localStatement(statement, s.now().UTC())
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commitState(context.Background(), func() error {
		previous, ok := s.latestStatement(prepared.Source, prepared.SourceRecordID)
		if ok && previous.RawRecordDigest == prepared.RawRecordDigest {
			return nil
		}
		if ok {
			prepared.SupersedesID = previous.ID
			if !prepared.ImportedAt.After(previous.ImportedAt) {
				prepared.ImportedAt = previous.ImportedAt.Add(time.Nanosecond)
			}
		}
		if prepared.ID.IsZero() {
			prepared.ID, err = id.New()
			if err != nil {
				return err
			}
		}
		s.statements = append(s.statements, prepared)
		_, err = s.publishSnapshot(s.now().UTC())
		return err
	})
}

func (s *Service) recordDenial(runID id.ID, target asset.Target, addr netip.Addr, code string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.catalog.AddTarget(target)
	s.appendObservation(Observation{
		ScanRunID: runID, ObservationPointID: s.pointID, Type: "host_reachability",
		SubjectKey: "ip:" + addr.String(), ObservedAt: now, CollectedAt: now, ResultStatus: "not_scanned",
		ValueSchemaVersion: "1", Value: map[string]any{"address": addr.String(), "reason": code}, SourceKind: "network",
	})
	return s.flush(context.Background())
}

func (s *Service) audit(grantID id.ID, action string, actor id.ID) error {
	grant, ok := s.grants[grantID]
	if !ok {
		return fmt.Errorf("audit grant %s: grant is missing", grantID)
	}
	content, err := grantContent(grant)
	if err != nil {
		return err
	}
	revisionID, err := id.New()
	if err != nil {
		return err
	}
	s.revisions = append(s.revisions, Revision{ID: revisionID, GrantID: grantID, Action: action, ActorID: actor, Content: content, At: s.now().UTC()})
	return nil
}

func grantContent(grant scope.Grant) ([]byte, error) {
	subjectID := ""
	if grant.SubjectID != nil {
		subjectID = grant.SubjectID.String()
	}
	approvedBy := ""
	if grant.ApprovedBy != nil {
		approvedBy = grant.ApprovedBy.String()
	}
	payload := struct {
		ID                string            `json:"id"`
		Name              string            `json:"name"`
		SubjectType       string            `json:"subject_type"`
		SubjectID         string            `json:"subject_id,omitempty"`
		Selectors         []scope.Selector  `json:"selectors"`
		Transports        []string          `json:"transports"`
		Ports             []scope.PortRange `json:"ports"`
		Operations        []string          `json:"operations"`
		Points            []id.ID           `json:"observation_point_ids"`
		ValidFrom         time.Time         `json:"valid_from"`
		ValidUntil        *time.Time        `json:"valid_until,omitempty"`
		MaxTargets        int64             `json:"max_targets"`
		MaxAddresses      int64             `json:"max_addresses"`
		MaxConnections    int64             `json:"max_connections"`
		MaxRequests       int64             `json:"max_requests"`
		MaxConcurrency    int               `json:"max_concurrency"`
		MaxRatePerSecond  float64           `json:"max_rate_per_second"`
		MaxRuntimeSeconds int64             `json:"max_runtime_seconds"`
		MaxEvidenceBytes  int64             `json:"max_evidence_bytes"`
		Status            string            `json:"status"`
		ApprovedBy        string            `json:"approved_by,omitempty"`
		ApprovedAt        *time.Time        `json:"approved_at,omitempty"`
		RevokedAt         *time.Time        `json:"revoked_at,omitempty"`
		RevocationReason  string            `json:"revocation_reason,omitempty"`
	}{
		ID: grant.ID.String(), Name: grant.Name, SubjectType: grant.SubjectType, SubjectID: subjectID,
		Selectors: grant.Selectors, Transports: grant.AllowedTransports, Ports: grant.Ports, Operations: grant.AllowedOperations,
		Points: grant.ObservationPointIDs, ValidFrom: grant.ValidFrom.UTC(), ValidUntil: grant.ValidUntil,
		MaxTargets: grant.MaxTargets, MaxAddresses: grant.MaxAddresses, MaxConnections: grant.MaxConnections, MaxRequests: grant.MaxRequests,
		MaxConcurrency: grant.MaxConcurrency, MaxRatePerSecond: grant.MaxRatePerSecond, MaxRuntimeSeconds: int64(grant.MaxRuntime / time.Second),
		MaxEvidenceBytes: grant.MaxEvidenceBytes, Status: grant.Status, ApprovedBy: approvedBy, ApprovedAt: grant.ApprovedAt,
		RevokedAt: grant.RevokedAt, RevocationReason: grant.RevocationReason,
	}
	return json.Marshal(payload)
}

func (s *Service) reconcileEvidence(ctx context.Context) error {
	known := map[string]string{}
	for _, row := range s.evidenceRows {
		if row.IntegrityStatus == "verified" || row.IntegrityStatus == "pending" {
			known[row.StorageKey] = row.ContentDigest
		}
	}
	_, missing, mismatch, err := s.evidence.Reconcile(known)
	if err != nil {
		return err
	}
	missingSet := map[string]struct{}{}
	mismatchSet := map[string]struct{}{}
	for _, key := range missing {
		missingSet[key] = struct{}{}
	}
	for _, key := range mismatch {
		mismatchSet[key] = struct{}{}
	}
	changed := false
	for i := range s.evidenceRows {
		if _, ok := missingSet[s.evidenceRows[i].StorageKey]; ok && s.evidenceRows[i].IntegrityStatus != "missing" {
			s.evidenceRows[i].IntegrityStatus = "missing"
			changed = true
		}
		if _, ok := mismatchSet[s.evidenceRows[i].StorageKey]; ok && s.evidenceRows[i].IntegrityStatus != "mismatch" {
			s.evidenceRows[i].IntegrityStatus = "mismatch"
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return s.flush(ctx)
}

func versionedRun(run task.Run) task.Run {
	run.ProbeProfileVersion = "builtin-1"
	run.FingerprintPackVersion = identity.PackVersion
	run.RulePackVersion = "builtin-1"
	run.ProductCatalogVersion = "builtin-1"
	return run
}

func containsOperation(grant scope.Grant, operation string) bool {
	for _, item := range grant.AllowedOperations {
		if item == operation {
			return true
		}
	}
	return false
}

func defaultResolver(ctx context.Context, host string) (Resolution, error) {
	resolver := net.Resolver{}
	var resolution Resolution
	cname, cnameErr := resolver.LookupCNAME(ctx, host)
	if cnameErr != nil {
		resolution.CanonicalError = cnameErr.Error()
	} else {
		resolution.CanonicalName = cname
	}
	addrs, err := resolver.LookupNetIP(ctx, "ip", host)
	resolution.Addresses = addrs
	return resolution, err
}

func digestOf(value any) string {
	buf, _ := json.Marshal(value)
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}
