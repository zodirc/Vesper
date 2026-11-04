package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/zodirc/Vesper/internal/assess"
	"github.com/zodirc/Vesper/internal/collect"
	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/identity"
	"github.com/zodirc/Vesper/internal/probe/arpprobe"
	"github.com/zodirc/Vesper/internal/probe/boltprobe"
	"github.com/zodirc/Vesper/internal/probe/clickhouseprobe"
	"github.com/zodirc/Vesper/internal/probe/cqlprobe"
	"github.com/zodirc/Vesper/internal/probe/ftpprobe"
	"github.com/zodirc/Vesper/internal/probe/httpprobe"
	"github.com/zodirc/Vesper/internal/probe/icmpprobe"
	"github.com/zodirc/Vesper/internal/probe/memcachedprobe"
	"github.com/zodirc/Vesper/internal/probe/mongoprobe"
	"github.com/zodirc/Vesper/internal/probe/mysqlprobe"
	"github.com/zodirc/Vesper/internal/probe/pgprobe"
	"github.com/zodirc/Vesper/internal/probe/redisprobe"
	"github.com/zodirc/Vesper/internal/probe/smtpprobe"
	"github.com/zodirc/Vesper/internal/probe/sshprobe"
	"github.com/zodirc/Vesper/internal/probe/tcp"
	"github.com/zodirc/Vesper/internal/probe/tdsprobe"
	"github.com/zodirc/Vesper/internal/probe/tlsprobe"
	"github.com/zodirc/Vesper/internal/probe/tnsprobe"
	"github.com/zodirc/Vesper/internal/probe/udp"
	"github.com/zodirc/Vesper/internal/rule"
	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/internal/task"
	"github.com/zodirc/Vesper/pkg/probesdk"
)

type addressInput struct {
	Address  string `json:"address"`
	Ports    []int  `json:"ports"`
	Hostname string `json:"hostname"`
}

type probeInput struct {
	Address       string `json:"address"`
	Port          int    `json:"port"`
	Probe         string `json:"probe"`
	Hostname      string `json:"hostname"`
	SMTPTransport string `json:"smtp_transport,omitempty"`
}

type collectInput struct {
	Operations []string `json:"operations"`
}

// ExecuteAvailable 领取并执行一个单元。没有可执行单元时返回 false。
// ExecuteAvailable claims and executes one unit. It returns false when no unit is executable.
//
// 过期、领取、启动和结果提交都在同一个数据库事务里锁定任务行后更新。网络收发发生在事务之外。
// Expiry, claim, start, and result submission each lock the task rows and update them in one database transaction. Network transfer happens outside the transaction.
func (s *Service) ExecuteAvailable(ctx context.Context) (bool, error) {
	if err := s.resumePlanning(ctx); err != nil {
		return false, err
	}
	s.mu.Lock()
	var lease task.Lease
	var account *scope.Account
	claimed := false
	worked := false
	err := s.commitState(ctx, func() error {
		if err := s.expireGrants(); err != nil {
			return err
		}
		if err := s.releaseUnauthorized(s.now()); err != nil {
			return err
		}
		s.tasks.Expire(s.now())
		var claimErr error
		lease, claimErr = s.tasks.Claim(s.now(), s.worker)
		if errors.Is(claimErr, task.ErrNone) {
			return nil
		}
		if claimErr != nil {
			return claimErr
		}
		if err := s.tasks.Start(lease, s.now()); err != nil {
			return err
		}
		account = s.accounts[lease.RunID]
		if account == nil {
			worked = true
			return s.tasks.Fail(lease, false, "budget_missing", "budget ledger missing", s.now())
		}
		if s.baselines == nil {
			s.baselines = map[id.ID]scope.Usage{}
		}
		s.baselines[lease.AttemptID] = account.ExportUsage()
		claimed = true
		return nil
	})
	s.mu.Unlock()
	if err != nil {
		return false, err
	}
	if !claimed {
		return worked, nil
	}

	execErr := s.executeLease(ctx, lease, account)
	s.mu.Lock()
	defer s.mu.Unlock()
	if execErr != nil {
		retryable := retryableExecution(execErr)
		return true, s.commitState(ctx, func() error {
			if err := s.recordAttemptOutcome(lease, s.now()); err != nil {
				return err
			}
			return s.tasks.Fail(lease, retryable, "execution_error", execErr.Error(), s.now())
		})
	}
	return true, s.commitState(ctx, func() error {
		if err := s.recordAttemptOutcome(lease, s.now()); err != nil {
			return err
		}
		return s.tasks.Succeed(lease, s.now())
	})
}

// retryableExecution 按设计区分可重试错误。预算耗尽、授权拒绝、取消、不支持和输入错误不重试。
// retryableExecution separates retryable errors as designed. Budget exhaustion, authorization denial, cancellation, unsupported work, and bad input are not retried.
func retryableExecution(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var probeErr *probesdk.Error
	if errors.As(err, &probeErr) {
		switch probeErr.Class {
		case probesdk.ClassTimeout, probesdk.ClassEvidence:
			return true
		default:
			return false
		}
	}
	var syntax *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &syntax) || errors.As(err, &typeErr) {
		return false
	}
	return true
}

// recordAttemptOutcome 用预算账本差值写入本次尝试的消耗，并用该尝试产生的观察生成结果摘要。
// recordAttemptOutcome writes this attempt's consumption from the budget-ledger delta and builds the result summary from observations produced by that attempt.
func (s *Service) recordAttemptOutcome(lease task.Lease, now time.Time) error {
	baseline, ok := s.baselines[lease.AttemptID]
	if !ok {
		return nil
	}
	delete(s.baselines, lease.AttemptID)
	account := s.accounts[lease.RunID]
	if account == nil {
		return nil
	}
	current := account.ExportUsage()
	connections := current.Connections - baseline.Connections
	requests := current.Requests - baseline.Requests
	evidenceBytes := current.Evidence - baseline.Evidence
	if connections < 0 || requests < 0 || evidenceBytes < 0 {
		return fmt.Errorf("attempt usage baseline is ahead of the budget ledger")
	}
	summary, digest, err := s.attemptResult(lease.AttemptID)
	if err != nil {
		return err
	}
	return s.tasks.RecordOutcome(lease, connections, requests, evidenceBytes, summary, digest, now)
}

func (s *Service) attemptResult(attemptID id.ID) (json.RawMessage, string, error) {
	byStatus := map[string]int{}
	byType := map[string]int{}
	var parts []string
	for _, item := range s.observations {
		if item.StageAttemptID != attemptID {
			continue
		}
		byStatus[item.ResultStatus]++
		byType[item.Type]++
		parts = append(parts, item.Type+"|"+item.SubjectKey+"|"+item.ContentDigest)
	}
	summary, err := json.Marshal(struct {
		Observations int            `json:"observations"`
		ByStatus     map[string]int `json:"by_status,omitempty"`
		ByType       map[string]int `json:"by_type,omitempty"`
	}{len(parts), byStatus, byType})
	if err != nil {
		return nil, "", err
	}
	if len(parts) == 0 {
		return summary, "", nil
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return summary, hex.EncodeToString(sum[:]), nil
}

func (s *Service) releaseUnauthorized(now time.Time) error {
	runs, units, _ := s.tasks.Export()
	byRun := map[id.ID]task.Run{}
	for _, run := range runs {
		byRun[run.ID] = run
	}
	for _, unit := range units {
		if unit.Status != task.UnitQueued && unit.Status != task.UnitRetryWait {
			continue
		}
		run, ok := byRun[unit.ScanRunID]
		if !ok || run.Status != task.RunRunning {
			continue
		}
		if reason := s.claimDenial(run, unit, now); reason != "" {
			if err := s.tasks.MarkSkipped(unit.ID, reason, now); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Service) claimDenial(run task.Run, unit task.Unit, now time.Time) string {
	grant, ok := s.frozen[run.ID]
	if !ok {
		return "grant_snapshot_missing"
	}
	live, ok := s.grants[grant.ID]
	if !ok {
		return "grant_not_active"
	}
	now = now.UTC()
	if live.Status == scope.StatusRevoked {
		return "grant_revoked"
	}
	if live.Status == scope.StatusExpired || (live.Status == scope.StatusActive && live.ValidUntil != nil && !now.Before(live.ValidUntil.UTC())) {
		return "grant_expired"
	}
	if live.Status != scope.StatusActive {
		return "grant_not_active"
	}
	allowedPoint := false
	for _, pointID := range grant.ObservationPointIDs {
		if pointID == unit.ObservationPointID {
			allowedPoint = true
			break
		}
	}
	if !allowedPoint {
		return "observation_point_denied"
	}
	if !containsOperation(grant, operationForUnit(unit.UnitType)) {
		return "operation_denied"
	}
	return ""
}

func operationForUnit(unitType string) string {
	switch unitType {
	case "host_discovery":
		return scope.OpDiscovery
	case "port_scan":
		return scope.OpConnect
	case "protocol_probe", "udp_probe":
		return scope.OpProtocolProbe
	case "host_collect":
		return scope.OpConfigCheck
	case "active_detection":
		return scope.OpActiveCheck
	default:
		return ""
	}
}

// Cancel 取消扫描运行。已经完成的观察保留，取消之后不再创建新的执行单元。
// Cancel cancels a scan run. Observations that already completed are kept, and no new execution unit is created after cancellation.
func (s *Service) Cancel(runID id.ID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commitState(context.Background(), func() error {
		return s.tasks.Cancel(runID, s.now())
	})
}

// Run 返回扫描运行副本。
// Run returns a copy of the scan run.
func (s *Service) Run(runID id.ID) (task.Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, _, err := s.tasks.Snapshot(runID)
	return run, err
}

// Observations 返回某次运行的观察副本。
// Observations returns copies of observations for one run.
func (s *Service) Observations(runID id.ID) []Observation {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Observation
	for _, item := range s.observations {
		if item.ScanRunID == runID {
			out = append(out, item)
		}
	}
	return out
}

// Hypotheses 返回识别候选副本。
// Hypotheses returns copies of identification candidates.
func (s *Service) Hypotheses() []identity.Hypothesis {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]identity.Hypothesis(nil), s.hypotheses...)
}

// Findings 返回当前风险视图副本。
// Findings returns copies of the current risk view.
func (s *Service) Findings() []Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	out := make([]Finding, 0, len(s.findings))
	for _, item := range s.findings {
		s.projectFinding(item, now)
		copied := *item
		if item.ResolvedAt != nil {
			at := item.ResolvedAt.UTC()
			copied.ResolvedAt = &at
		}
		out = append(out, copied)
	}
	return out
}

func (s *Service) executeLease(ctx context.Context, lease task.Lease, account *scope.Account) error {
	s.mu.Lock()
	err := s.commitState(ctx, func() error {
		return s.tasks.Renew(lease, s.now())
	})
	s.mu.Unlock()
	if err != nil {
		return err
	}
	switch lease.UnitType {
	case "host_discovery", "port_scan":
		return s.executePorts(ctx, lease, account, lease.UnitType == "host_discovery")
	case "udp_probe":
		return s.executeUDP(ctx, lease, account)
	case "protocol_probe":
		return s.executeProbe(ctx, lease, account)
	case "host_collect":
		return s.executeCollect(ctx, lease)
	case "active_detection":
		return s.executeActive(ctx, lease, account)
	default:
		return &probesdk.Error{Class: probesdk.ClassUnsupported, Message: "unit type " + lease.UnitType}
	}
}

func (s *Service) executePorts(ctx context.Context, lease task.Lease, account *scope.Account, discovery bool) error {
	var input addressInput
	if err := json.Unmarshal(lease.Input, &input); err != nil {
		return err
	}
	addr, err := netip.ParseAddr(input.Address)
	if err != nil {
		return err
	}
	s.mu.Lock()
	concurrency := s.frozen[lease.RunID].MaxConcurrency
	portUnit, summarize := s.portScanDependency(lease)
	tcpState := ""
	if discovery && summarize {
		tcpState = s.observedReachability(portUnit, addr)
	}
	s.mu.Unlock()
	if concurrency < 1 {
		return &probesdk.Error{Class: probesdk.ClassExecution, Message: "grant concurrency is not configured"}
	}
	if discovery {
		if summarize {
			return s.finishSummarizedDiscovery(ctx, lease, account, addr, tcpState)
		}
		return s.finishDirectDiscovery(ctx, lease, account, addr, input.Ports, concurrency)
	}
	results := tcp.Scan(ctx, s.dialer(lease, account), addr, input.Ports, concurrency, scope.OpConnect, s.now)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commitState(ctx, func() error {
		run, _, err := s.tasks.Snapshot(lease.RunID)
		if err != nil {
			return err
		}
		createProbes := run.Status == task.RunRunning
		for _, result := range results {
			endpoint := s.catalog.ObserveEndpoint(addr, "tcp", result.Port, endpointState(result.State), result.ObservedAt)
			endpointID := endpoint.ID
			s.appendObservation(Observation{
				ScanRunID: lease.RunID, ScanUnitID: lease.UnitID, StageAttemptID: lease.AttemptID, EndpointID: &endpointID,
				ObservationPointID: lease.ObservationPointID, Type: "port_state", SubjectKey: fmt.Sprintf("tcp:%s:%d", addr.String(), result.Port),
				ObservedAt: result.ObservedAt, CollectedAt: s.now(), ResultStatus: portResultStatus(result.State),
				ValueSchemaVersion: "1", Value: map[string]any{"state": result.State, "port": result.Port, "address": addr.String()},
				SourceKind: "network",
			})
			if result.State != "open" || !createProbes {
				continue
			}
			probes := []string{"http", "tls", "ssh"}
			if ftpProbeForPort(result.Port) == ftpprobe.Name {
				probes = append(probes, ftpprobe.Name)
			}
			smtpTransport, smtpSelected := smtpProbeForPort(result.Port)
			if smtpSelected {
				probes = append(probes, smtpprobe.Name)
			}
			if mysqlProbeForPort(result.Port) == mysqlprobe.Name {
				probes = append(probes, mysqlprobe.Name)
			}
			if pgProbeForPort(result.Port) == pgprobe.Name {
				probes = append(probes, pgprobe.Name)
			}
			if redisProbeForPort(result.Port) == redisprobe.Name {
				probes = append(probes, redisprobe.Name)
			}
			if mongoProbeForPort(result.Port) == mongoprobe.Name {
				probes = append(probes, mongoprobe.Name)
			}
			if tdsProbeForPort(result.Port) == tdsprobe.Name {
				probes = append(probes, tdsprobe.Name)
			}
			if tnsProbeForPort(result.Port) == tnsprobe.Name {
				probes = append(probes, tnsprobe.Name)
			}
			if cqlProbeForPort(result.Port) == cqlprobe.Name {
				probes = append(probes, cqlprobe.Name)
			}
			if boltProbeForPort(result.Port) == boltprobe.Name {
				probes = append(probes, boltprobe.Name)
			}
			if memcachedProbeForPort(result.Port) == memcachedprobe.Name {
				probes = append(probes, memcachedprobe.Name)
			}
			if clickHouseProbeForPort(result.Port) == clickhouseprobe.Name {
				probes = append(probes, clickhouseprobe.Name)
			}
			for _, probe := range probes {
				item := probeInput{Address: addr.String(), Port: result.Port, Probe: probe, Hostname: input.Hostname}
				if probe == smtpprobe.Name {
					item.SMTPTransport = smtpTransport
				}
				payload, err := json.Marshal(item)
				if err != nil {
					return err
				}
				unit := task.Unit{
					ScanRunID: lease.RunID, TargetID: lease.TargetID, ObservationPointID: lease.ObservationPointID,
					UnitType: "protocol_probe", StageKey: fmt.Sprintf("protocol_probe:%s:%s:%d", probe, addr.String(), result.Port),
					DependsOn: []id.ID{lease.UnitID}, RequiredCapabilities: []string{"protocol_" + probe}, Input: payload, Priority: 2, CreatedAt: s.now(),
				}
				if err := s.tasks.AddUnit(unit); err != nil && !errors.Is(err, task.ErrDuplicateStage) {
					return err
				}
			}
		}
		return nil
	})
}

// udpProbeForPort 选择 UDP 探针。生产实现只在端口 53 选择 DNS。本包测试可以替换它，把 DNS 指到临时端口。
// udpProbeForPort selects a UDP probe. The production implementation selects DNS only for port 53. Tests in this package may replace it to point DNS at an ephemeral port.
var udpProbeForPort = udp.ProbeForPort

// ftpProbeForPort 选择 FTP 探针。生产实现只在端口 21 选择 FTP。本包测试可以替换它，把 FTP 指到临时端口。
// ftpProbeForPort selects the FTP probe. The production implementation selects FTP only for port 21. Tests in this package may replace it to point FTP at an ephemeral port.
var ftpProbeForPort = ftpprobe.ProbeForPort

// smtpProbeForPort 选择 SMTP 传输。生产实现中 25 和 587 为明文，465 为 TLS。本包测试可以替换它，把 SMTP 指到临时端口。
// smtpProbeForPort selects the SMTP transport. In production, ports 25 and 587 are plaintext and port 465 is TLS. Tests in this package may replace it to point SMTP at an ephemeral port.
var smtpProbeForPort = smtpprobe.ProbeForPort

// mysqlProbeForPort 选择 MySQL 探针。生产实现只在端口 3306 选择 MySQL。本包测试可以替换它，把 MySQL 指到临时端口。
// mysqlProbeForPort selects the MySQL probe. The production implementation selects MySQL only for port 3306. Tests in this package may replace it to point MySQL at an ephemeral port.
var mysqlProbeForPort = mysqlprobe.ProbeForPort

// pgProbeForPort 选择 PostgreSQL 探针。生产实现只在端口 5432 选择 PostgreSQL。本包测试可以替换它，把 PostgreSQL 指到临时端口。
// pgProbeForPort selects the PostgreSQL probe. The production implementation selects PostgreSQL only for port 5432. Tests in this package may replace it to point PostgreSQL at an ephemeral port.
var pgProbeForPort = pgprobe.ProbeForPort

// redisProbeForPort 选择 Redis 探针。生产实现只在端口 6379 选择 Redis。本包测试可以替换它，把 Redis 指到临时端口。
// redisProbeForPort selects the Redis probe. The production implementation selects Redis only for port 6379. Tests in this package may replace it to point Redis at an ephemeral port.
var redisProbeForPort = redisprobe.ProbeForPort

// mongoProbeForPort 选择 MongoDB 探针。生产实现只在端口 27017 选择 MongoDB。本包测试可以替换它，把 MongoDB 指到临时端口。
// mongoProbeForPort selects the MongoDB probe. The production implementation selects MongoDB only for port 27017. Tests in this package may replace it to point MongoDB at an ephemeral port.
var mongoProbeForPort = mongoprobe.ProbeForPort

// tdsProbeForPort 选择 TDS 探针。生产实现只在端口 1433 选择 TDS。本包测试可以替换它，把 TDS 指到临时端口。
// tdsProbeForPort selects the TDS probe. The production implementation selects TDS only for port 1433. Tests in this package may replace it to point TDS at an ephemeral port.
var tdsProbeForPort = tdsprobe.ProbeForPort

// tnsProbeForPort 选择 TNS 探针。生产实现只在端口 1521 选择 TNS。本包测试可以替换它，把 TNS 指到临时端口。
// tnsProbeForPort selects the TNS probe. The production implementation selects TNS only for port 1521. Tests in this package may replace it to point TNS at an ephemeral port.
var tnsProbeForPort = tnsprobe.ProbeForPort

// cqlProbeForPort 选择 CQL 探针。生产实现只在端口 9042 选择 CQL。本包测试可以替换它，把 CQL 指到临时端口。
// cqlProbeForPort selects the CQL probe. The production implementation selects CQL only for port 9042. Tests in this package may replace it to point CQL at an ephemeral port.
var cqlProbeForPort = cqlprobe.ProbeForPort

// boltProbeForPort 选择 Bolt 探针。生产实现只在端口 7687 选择 Bolt。本包测试可以替换它，把 Bolt 指到临时端口。
// boltProbeForPort selects the Bolt probe. The production implementation selects Bolt only for port 7687. Tests in this package may replace it to point Bolt at an ephemeral port.
var boltProbeForPort = boltprobe.ProbeForPort

// memcachedProbeForPort 选择 Memcached 探针。生产实现只在端口 11211 选择 Memcached。本包测试可以替换它，把 Memcached 指到临时端口。
// memcachedProbeForPort selects the Memcached probe. The production implementation selects Memcached only for port 11211. Tests in this package may replace it to point Memcached at an ephemeral port.
var memcachedProbeForPort = memcachedprobe.ProbeForPort

// clickHouseProbeForPort 选择 ClickHouse 探针。生产实现只在端口 9000 选择 ClickHouse。本包测试可以替换它，把 ClickHouse 指到临时端口。
// clickHouseProbeForPort selects the ClickHouse probe. The production implementation selects ClickHouse only for port 9000. Tests in this package may replace it to point ClickHouse at an ephemeral port.
var clickHouseProbeForPort = clickhouseprobe.ProbeForPort

func (s *Service) executeUDP(ctx context.Context, lease task.Lease, account *scope.Account) error {
	var input addressInput
	if err := json.Unmarshal(lease.Input, &input); err != nil {
		return err
	}
	addr, err := netip.ParseAddr(input.Address)
	if err != nil {
		return err
	}
	dial := s.dialer(lease, account)
	var results []udp.Result
	var ports []int
	stop := false
	for _, port := range input.Ports {
		if stop || ctx.Err() != nil {
			ports = append(ports, port)
			message := "udp probe stopped"
			if ctx.Err() != nil {
				message = ctx.Err().Error()
			}
			results = append(results, udp.Result{Outcome: udp.Outcome{State: "not_scanned", Status: "not_scanned", Message: message}})
			continue
		}
		probeName := udpProbeForPort(port)
		limit := udp.ResponseLimit(probeName)
		result, err := udp.Execute(ctx, probeName, func(ctx context.Context, payload []byte) ([]byte, error) {
			if limit <= 0 {
				return nil, fmt.Errorf("udp probe %s: response limit is missing", probeName)
			}
			return dial.ExchangeUDP(ctx, addr, port, scope.OpProtocolProbe, payload, limit)
		}, input.Hostname)
		if err != nil {
			return err
		}
		ports = append(ports, port)
		results = append(results, result)
		if stopUDP(result.Outcome.State) {
			stop = true
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commitState(ctx, func() error {
		for i, result := range results {
			if err := s.recordUDP(lease, addr, input.Hostname, ports[i], result); err != nil {
				return err
			}
		}
		return nil
	})
}

func stopUDP(state string) bool {
	switch state {
	case "not_scanned", "unsupported", "error", "unreachable":
		return true
	default:
		return false
	}
}

func (s *Service) recordUDP(lease task.Lease, addr netip.Addr, hostname string, port int, result udp.Result) error {
	var evidenceIDs []id.ID
	var record *EvidenceRecord
	if len(result.Response) > 0 {
		if err := s.accounts[lease.RunID].TryEvidence(int64(len(result.Response))); err != nil {
			return &probesdk.Error{Class: probesdk.ClassBudget, Message: err.Error()}
		}
		object, err := s.evidence.Put(s.now(), result.Response)
		if err != nil {
			return &probesdk.Error{Class: probesdk.ClassEvidence, Message: err.Error()}
		}
		evidenceID, err := id.New()
		if err != nil {
			return err
		}
		storedAt := s.now()
		contentType, contentEncoding := evidenceContent(result.Probe)
		sourceModule := result.Probe + "probe"
		record = &EvidenceRecord{
			ID: evidenceID, EvidenceType: "raw_response", StorageKey: object.StorageKey, SizeBytes: object.SizeBytes,
			DigestAlgorithm: object.DigestAlgorithm, ContentDigest: object.ContentDigest, ContentType: contentType, ContentEncoding: contentEncoding,
			SourceModule: sourceModule, SourceAttemptID: lease.AttemptID, IntegrityStatus: "verified", Sensitivity: "internal",
			CapturedAt: storedAt, StoredAt: &storedAt,
		}
		s.evidenceRows = append(s.evidenceRows, *record)
		evidenceIDs = []id.ID{evidenceID}
	}
	value := map[string]any{
		"state": result.Outcome.State, "port": port, "address": addr.String(), "transport": "udp",
	}
	if hostname != "" {
		value["hostname"] = hostname
	}
	if result.Rounds > 0 {
		value["probe"] = result.Probe
		value["probe_version"] = result.Version
		value["connected_address"] = addr.String()
		value["request_rounds"] = result.Rounds
		value["response_bytes"] = len(result.Response)
		value["qname"] = result.QName
		value["qtype"] = dnsQTypeName(result.QType)
	}
	if result.Outcome.Message != "" {
		value["message"] = result.Outcome.Message
	}
	if record != nil {
		value["evidence_digest"] = record.ContentDigest
	}
	endpoint := s.catalog.ObserveEndpoint(addr, "udp", port, endpointState(result.Outcome.State), s.now())
	endpointID := endpoint.ID
	s.appendObservation(Observation{
		ScanRunID: lease.RunID, ScanUnitID: lease.UnitID, StageAttemptID: lease.AttemptID, EndpointID: &endpointID,
		ObservationPointID: lease.ObservationPointID, Type: "port_state", SubjectKey: fmt.Sprintf("udp:%s:%d", addr.String(), port),
		ObservedAt: s.now(), CollectedAt: s.now(), ResultStatus: udpResultStatus(result.Outcome), ValueSchemaVersion: "1", Value: value,
		EvidenceIDs: evidenceIDs, SourceKind: "network",
	})
	if result.Outcome.State != "open" {
		return nil
	}
	protocolValue := map[string]any{}
	for key, item := range value {
		protocolValue[key] = item
	}
	protocolValue["protocol"] = result.Probe
	_, created := s.appendObservation(Observation{
		ScanRunID: lease.RunID, ScanUnitID: lease.UnitID, StageAttemptID: lease.AttemptID, EndpointID: &endpointID,
		ObservationPointID: lease.ObservationPointID, Type: "protocol_response", SubjectKey: fmt.Sprintf("%s:%s:%d", result.Probe, addr.String(), port),
		ObservedAt: s.now(), CollectedAt: s.now(), ResultStatus: "observed", ValueSchemaVersion: "1", Value: protocolValue,
		EvidenceIDs: evidenceIDs, SourceKind: "network",
	})
	if created {
		return s.identify(lease.RunID, endpointID, lease.ObservationPointID)
	}
	return nil
}

func dnsQTypeName(qtype uint16) string {
	switch qtype {
	case 1:
		return "A"
	case 2:
		return "NS"
	default:
		return ""
	}
}

func udpResultStatus(outcome udp.Outcome) string {
	switch outcome.State {
	case "open", "closed":
		return "observed"
	case "no_response", "unreachable", "not_scanned", "unsupported", "error":
		return outcome.State
	case "unknown":
		switch outcome.Status {
		case "unsupported", "unreachable", "not_scanned", "error", "no_response":
			return outcome.Status
		default:
			return "observed"
		}
	default:
		return "error"
	}
}

func (s *Service) executeProbe(ctx context.Context, lease task.Lease, account *scope.Account) error {
	var input probeInput
	if err := json.Unmarshal(lease.Input, &input); err != nil {
		return err
	}
	addr, err := netip.ParseAddr(input.Address)
	if err != nil {
		return err
	}
	dial := s.dialer(lease, account)
	switch input.Probe {
	case "http":
		result, probeErr := httpprobe.Probe(ctx, dial, account, addr, input.Port, input.Hostname, 4096, s.now)
		value := map[string]any{"status_code": result.StatusCode, "headers": result.Headers}
		state := result.State
		if result.StatusCode > 0 {
			value["protocol"] = "http"
		} else if state == "open" {
			state = "error"
		}
		return s.finishProbe(ctx, lease, addr, input.Port, input.Hostname, "http", value, result.Raw, state, probeErr)
	case "tls":
		result, probeErr := tlsprobe.Probe(ctx, dial, account, addr, input.Port, input.Hostname, s.now)
		var cert []byte
		if len(result.PeerCerts) > 0 {
			cert = result.PeerCerts[0]
		}
		value := map[string]any{"version": result.Version, "subject": result.Subject, "issuer": result.Issuer}
		state := result.State
		if state == "open" {
			value["protocol"] = "tls"
		}
		return s.finishProbe(ctx, lease, addr, input.Port, input.Hostname, "tls", value, cert, state, probeErr)
	case "ssh":
		result, probeErr := sshprobe.Probe(ctx, dial, account, addr, input.Port, s.now)
		value := map[string]any{"banner": result.Banner}
		state := result.State
		if result.IsSSH {
			value["protocol"] = "ssh"
		} else if state == "open" {
			state = "error"
		}
		return s.finishProbe(ctx, lease, addr, input.Port, input.Hostname, "ssh", value, result.Raw, state, probeErr)
	case ftpprobe.Name:
		result, probeErr := ftpprobe.Probe(ctx, dial, account, addr, input.Port, s.now)
		value := map[string]any{"banner": result.Banner}
		state := result.State
		if result.ReplyCode != "" {
			value["reply_code"] = result.ReplyCode
		}
		if result.IsFTP {
			value["protocol"] = ftpprobe.Name
		} else if state == "open" {
			state = "error"
		}
		return s.finishProbe(ctx, lease, addr, input.Port, input.Hostname, ftpprobe.Name, value, result.Raw, state, probeErr)
	case smtpprobe.Name:
		result, probeErr := smtpprobe.Probe(ctx, dial, account, addr, input.Port, input.Hostname, input.SMTPTransport, s.now)
		value := map[string]any{"banner": result.Banner}
		state := result.State
		if result.ReplyCode != "" {
			value["reply_code"] = result.ReplyCode
		}
		if result.IsSMTP {
			value["protocol"] = smtpprobe.Name
		} else if state == "open" {
			state = "error"
		}
		return s.finishProbe(ctx, lease, addr, input.Port, input.Hostname, smtpprobe.Name, value, result.Raw, state, probeErr)
	case mysqlprobe.Name:
		result, probeErr := mysqlprobe.Probe(ctx, dial, account, addr, input.Port, s.now)
		value := map[string]any{}
		state := result.State
		if result.IsMySQL {
			value["protocol"] = mysqlprobe.Name
			value["protocol_version"] = result.ProtocolVersion
			value["server_version"] = result.ServerVersion
		} else if state == "open" {
			state = "error"
		}
		return s.finishProbe(ctx, lease, addr, input.Port, input.Hostname, mysqlprobe.Name, value, result.Raw, state, probeErr)
	case pgprobe.Name:
		result, probeErr := pgprobe.Probe(ctx, dial, account, addr, input.Port, s.now)
		value := map[string]any{}
		state := result.State
		if result.IsPostgreSQL {
			value["protocol"] = pgprobe.Name
			value["message_type"] = result.MessageType
			if result.MessageType == "R" {
				value["auth_method"] = result.AuthMethod
			}
		} else if state == "open" {
			state = "error"
		}
		return s.finishProbe(ctx, lease, addr, input.Port, input.Hostname, pgprobe.Name, value, result.Raw, state, probeErr)
	case redisprobe.Name:
		result, probeErr := redisprobe.Probe(ctx, dial, account, addr, input.Port, s.now)
		value := map[string]any{}
		state := result.State
		if result.IsRedis {
			value["protocol"] = redisprobe.Name
			value["reply"] = result.Reply
		} else if state == "open" {
			state = "error"
		}
		return s.finishProbe(ctx, lease, addr, input.Port, input.Hostname, redisprobe.Name, value, result.Raw, state, probeErr)
	case mongoprobe.Name:
		result, probeErr := mongoprobe.Probe(ctx, dial, account, addr, input.Port, s.now)
		value := map[string]any{}
		state := result.State
		if result.IsMongoDB {
			value["protocol"] = mongoprobe.Name
			value["reply"] = result.Reply
		} else if state == "open" {
			state = "error"
		}
		return s.finishProbe(ctx, lease, addr, input.Port, input.Hostname, mongoprobe.Name, value, result.Raw, state, probeErr)
	case tdsprobe.Name:
		result, probeErr := tdsprobe.Probe(ctx, dial, account, addr, input.Port, s.now)
		value := map[string]any{}
		state := result.State
		if result.IsTDS {
			value["protocol"] = tdsprobe.Name
			value["server_version"] = result.ServerVersion
			value["encryption"] = result.Encryption
		} else if state == "open" {
			state = "error"
		}
		return s.finishProbe(ctx, lease, addr, input.Port, input.Hostname, tdsprobe.Name, value, result.Raw, state, probeErr)
	case tnsprobe.Name:
		result, probeErr := tnsprobe.Probe(ctx, dial, account, addr, input.Port, s.now)
		value := map[string]any{}
		state := result.State
		if result.IsTNS {
			value["protocol"] = tnsprobe.Name
			if result.ServerVersion != "" {
				value["server_version"] = result.ServerVersion
			}
			if result.ErrorCode >= 0 {
				value["error_code"] = result.ErrorCode
			}
		} else if state == "open" {
			state = "error"
		}
		return s.finishProbe(ctx, lease, addr, input.Port, input.Hostname, tnsprobe.Name, value, result.Raw, state, probeErr)
	case cqlprobe.Name:
		result, probeErr := cqlprobe.Probe(ctx, dial, account, addr, input.Port, s.now)
		value := map[string]any{}
		state := result.State
		if result.IsCQL {
			value["protocol"] = cqlprobe.Name
			value["protocol_version"] = result.ProtocolVersion
			value["reply"] = result.Reply
		} else if state == "open" {
			state = "error"
		}
		return s.finishProbe(ctx, lease, addr, input.Port, input.Hostname, cqlprobe.Name, value, result.Raw, state, probeErr)
	case boltprobe.Name:
		result, probeErr := boltprobe.Probe(ctx, dial, account, addr, input.Port, s.now)
		value := map[string]any{}
		state := result.State
		if result.IsBolt {
			value["protocol"] = boltprobe.Name
			value["protocol_version"] = result.ProtocolVersion
		} else if state == "open" {
			state = "error"
		}
		return s.finishProbe(ctx, lease, addr, input.Port, input.Hostname, boltprobe.Name, value, result.Raw, state, probeErr)
	case memcachedprobe.Name:
		result, probeErr := memcachedprobe.Probe(ctx, dial, account, addr, input.Port, s.now)
		value := map[string]any{}
		state := result.State
		if result.IsMemcached {
			value["protocol"] = memcachedprobe.Name
			value["server_version"] = result.ServerVersion
		} else if state == "open" {
			state = "error"
		}
		return s.finishProbe(ctx, lease, addr, input.Port, input.Hostname, memcachedprobe.Name, value, result.Raw, state, probeErr)
	case clickhouseprobe.Name:
		result, probeErr := clickhouseprobe.Probe(ctx, dial, account, addr, input.Port, s.now)
		value := map[string]any{}
		state := result.State
		if result.IsClickHouse {
			value["protocol"] = clickhouseprobe.Name
			value["reply"] = result.Reply
			if result.Reply == clickhouseprobe.ReplyHello {
				value["server_version"] = result.ServerVersion
				value["protocol_revision"] = result.ProtocolRevision
			} else {
				value["exception_code"] = result.ExceptionCode
				value["exception_name"] = result.ExceptionName
			}
		} else if state == "open" {
			state = "error"
		}
		return s.finishProbe(ctx, lease, addr, input.Port, input.Hostname, clickhouseprobe.Name, value, result.Raw, state, probeErr)
	default:
		return &probesdk.Error{Class: probesdk.ClassUnsupported, Message: "probe " + input.Probe}
	}
}

func (s *Service) finishProbe(ctx context.Context, lease task.Lease, addr netip.Addr, port int, hostname, protocol string, value map[string]any, raw []byte, state string, probeErr error) error {
	var evidenceIDs []id.ID
	var record *EvidenceRecord
	if len(raw) > 0 {
		if err := s.accounts[lease.RunID].TryEvidence(int64(len(raw))); err != nil {
			return &probesdk.Error{Class: probesdk.ClassBudget, Message: err.Error()}
		}
		object, err := s.evidence.Put(s.now(), raw)
		if err != nil {
			return &probesdk.Error{Class: probesdk.ClassEvidence, Message: err.Error()}
		}
		evidenceID, err := id.New()
		if err != nil {
			return err
		}
		storedAt := s.now()
		evidenceType := "raw_response"
		if protocol == "tls" {
			evidenceType = "tls_certificate"
		}
		// 设计要求证据带有敏感级，但没有规定协议响应属于哪一级。探测内容按 internal 保存。
		// The design requires an evidence sensitivity and does not assign protocol responses to one level. Probe content is stored as internal.
		contentType, contentEncoding := evidenceContent(protocol)
		record = &EvidenceRecord{
			ID: evidenceID, EvidenceType: evidenceType, StorageKey: object.StorageKey, SizeBytes: object.SizeBytes,
			DigestAlgorithm: object.DigestAlgorithm, ContentDigest: object.ContentDigest, ContentType: contentType, ContentEncoding: contentEncoding,
			SourceModule: protocol + "probe", SourceAttemptID: lease.AttemptID, IntegrityStatus: "verified", Sensitivity: "internal",
			CapturedAt: storedAt, StoredAt: &storedAt,
		}
		evidenceIDs = []id.ID{evidenceID}
	}
	if record != nil && value != nil {
		value["evidence_digest"] = record.ContentDigest
	}
	status := "observed"
	if state != "open" {
		status = "error"
		if state == "no_response" || state == "not_scanned" || state == "unsupported" {
			status = state
		}
	}
	if probeErr != nil && state == "open" {
		status = "partial"
	}
	if value == nil {
		value = map[string]any{}
	}
	value["probe"] = protocol
	value["probe_version"] = "builtin-1"
	value["address"] = addr.String()
	value["connected_address"] = addr.String()
	value["port"] = port
	value["transport"] = "tcp"
	value["request_rounds"] = 1
	value["response_bytes"] = len(raw)
	if hostname != "" {
		value["hostname"] = hostname
	}
	if probeErr != nil {
		value["error"] = probeErr.Error()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if record != nil {
		s.evidenceRows = append(s.evidenceRows, *record)
	}
	endpoint := s.catalog.ObserveEndpoint(addr, "tcp", port, "open", s.now())
	endpointID := endpoint.ID
	_, created := s.appendObservation(Observation{
		ScanRunID: lease.RunID, ScanUnitID: lease.UnitID, StageAttemptID: lease.AttemptID, EndpointID: &endpointID,
		ObservationPointID: lease.ObservationPointID, Type: "protocol_response", SubjectKey: fmt.Sprintf("%s:%s:%d", protocol, addr.String(), port),
		ObservedAt: s.now(), CollectedAt: s.now(), ResultStatus: status, ValueSchemaVersion: "1", Value: value,
		EvidenceIDs: evidenceIDs, SourceKind: "network",
	})
	if created && (status == "observed" || status == "partial") {
		if err := s.identify(lease.RunID, endpointID, lease.ObservationPointID); err != nil {
			return err
		}
		if protocol == "http" {
			if err := s.scheduleActiveDetection(lease, addr, port, hostname); err != nil {
				return err
			}
		}
	}
	return s.flush(ctx)
}

func (s *Service) executeCollect(ctx context.Context, lease task.Lease) error {
	var input collectInput
	if err := json.Unmarshal(lease.Input, &input); err != nil {
		return err
	}
	results, err := collect.CollectRequested(input.Operations)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var assetID id.ID
	for _, result := range results {
		if result.MachineIDHash == "" || !assetID.IsZero() {
			continue
		}
		if machine, ok := s.catalog.ObserveMachine(result.MachineIDHash, result.PlatformFamily, result.PlatformName, result.PlatformVersion, s.now()); ok {
			assetID = machine.ID
		}
	}
	for _, result := range results {
		value := map[string]any{}
		for key, item := range result.Value {
			value[key] = item
		}
		value["collection_status"] = result.Status
		_, created := s.appendObservation(Observation{
			ScanRunID: lease.RunID, ScanUnitID: lease.UnitID, StageAttemptID: lease.AttemptID, AssetID: assetID,
			ObservationPointID: lease.ObservationPointID, Type: "host_inventory", SubjectKey: "local:" + result.Operation,
			ObservedAt: s.now(), CollectedAt: s.now(), ResultStatus: observationStatusForCollection(result.Status), ValueSchemaVersion: "1",
			Value: value, SourceKind: "local_collector",
		})
		if created && result.Operation == "collect_os_info" && !assetID.IsZero() {
			if err := s.evaluateConfig(lease, assetID); err != nil {
				return err
			}
		}
	}
	return s.flush(ctx)
}

// evaluateConfig 读取本次扫描的主机采集事实。内置规则按运行上的规则包版本选择；计划里冻结的配置包即使随后被弃用也参与判断。
// evaluateConfig reads the host-collection facts of this scan. Built-in rules are selected by the run's rule-pack version. Configuration packs frozen into the plan are evaluated even if they are deprecated afterward.
func (s *Service) evaluateConfig(lease task.Lease, assetID id.ID) error {
	var facts []rule.Fact
	for _, item := range s.observations {
		if item.ScanRunID != lease.RunID || item.Type != "host_inventory" {
			continue
		}
		facts = append(facts, rule.Fact{ID: item.ID, Type: item.Type, Subject: item.SubjectKey, ResultStatus: item.ResultStatus, Value: item.Value})
	}
	version := rule.ConfigVersion
	var extras []string
	var onlyKey string
	if run, _, err := s.tasks.Snapshot(lease.RunID); err == nil {
		if run.RulePackVersion != "" {
			version = run.RulePackVersion
		}
		var plan planBody
		if len(run.Plan) > 0 {
			if err := json.Unmarshal(run.Plan, &plan); err != nil {
				return err
			}
			extras = plan.ConfigRules
			onlyKey = plan.VulnerabilityID
		}
	}
	rules := rule.Configs(s.packs, version)
	for _, extra := range extras {
		rules = append(rules, rule.FrozenConfigs(s.packs, extra)...)
	}
	if onlyKey != "" {
		rules = selectConfigRules(rules, onlyKey)
	}
	var inputs []id.ID
	for _, fact := range facts {
		if !fact.ID.IsZero() {
			inputs = append(inputs, fact.ID)
		}
	}
	assessmentID := id.MustNew()
	for _, decision := range rule.EvaluateConfigs(rules, facts) {
		matched, err := marshalCondition(decision.Matched)
		if err != nil {
			return err
		}
		unmatched, err := marshalCondition(decision.Unmatched)
		if err != nil {
			return err
		}
		detectionID := id.MustNew()
		s.detections = append(s.detections, Detection{
			ID: detectionID, AssessmentRunID: assessmentID, SubjectType: "asset", SubjectID: assetID,
			RuleID: decision.RuleID, RuleVersion: decision.RuleVersion, VulnerabilityID: decision.RuleKey,
			ResultStatus: decision.Status, Severity: decision.Severity, Summary: decision.Summary,
			Matched: matched, Unmatched: unmatched,
			InputObservationIDs: append([]id.ID(nil), inputs...), EvaluatedAt: s.now(),
		})
		if decision.Status != "confirmed" {
			continue
		}
		s.mergeFinding(id.ID{}, assetID, decision.RuleKey, detectionID, assessmentID, decision.RuleKey, "misconfiguration", decision.Severity, nil, decision.RuleID, id.ID{})
		if decision.Title != "" {
			if finding := s.findings[assetID.String()+"|"+decision.RuleKey]; finding != nil {
				finding.Title = decision.Title
			}
		}
	}
	return nil
}

func selectConfigRules(rules []rule.ConfigRule, key string) []rule.ConfigRule {
	var out []rule.ConfigRule
	for _, item := range rules {
		if item.Key == key {
			out = append(out, item)
		}
	}
	return out
}

func marshalCondition(value map[string]any) (json.RawMessage, error) {
	if len(value) == 0 {
		return nil, nil
	}
	return json.Marshal(value)
}

// identify 把该端点已有观察交给指纹引擎。规则未声明证据类型时只读取 protocol_response。
// identify gives the endpoint's existing observations to the fingerprint engine. A rule with no declared evidence types reads only protocol_response.
func (s *Service) identify(runID, endpointID, pointID id.ID) error {
	var views []identity.ObservationView
	for _, item := range s.observations {
		if item.EndpointID != nil && *item.EndpointID == endpointID {
			views = append(views, identity.ObservationView{ID: item.ID, Type: item.Type, Value: item.Value})
		}
	}
	version := identity.PackVersion
	var extras []string
	if run, _, err := s.tasks.Snapshot(runID); err == nil {
		if run.FingerprintPackVersion != "" {
			version = run.FingerprintPackVersion
		}
		var plan planBody
		if len(run.Plan) > 0 {
			if err := json.Unmarshal(run.Plan, &plan); err != nil {
				return err
			}
			extras = plan.NmapFingerprints
		}
	}
	for i := range views {
		response, err := s.observationResponse(views[i].ID)
		if err != nil {
			return err
		}
		views[i].Response = response
	}
	rules := rule.Fingerprints(s.packs, version)
	for _, extra := range extras {
		rules = append(rules, rule.FrozenFingerprints(s.packs, extra)...)
	}
	found := identity.Identify(endpointID, pointID, views, rules, version, s.aliases, s.now())
	seen := map[string]struct{}{}
	for _, item := range s.hypotheses {
		seen[hypothesisKey(item)] = struct{}{}
	}
	for _, item := range found {
		key := hypothesisKey(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		s.hypotheses = append(s.hypotheses, item)
		var snapshotID id.ID
		if run, _, err := s.tasks.Snapshot(runID); err == nil {
			snapshotID = run.IntelSnapshotID
		}
		if err := s.judgeHypothesis(snapshotID, item); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) observationResponse(observationID id.ID) ([]byte, error) {
	var evidenceIDs []id.ID
	for _, item := range s.observations {
		if item.ID == observationID && item.Type == "protocol_response" {
			evidenceIDs = append([]id.ID(nil), item.EvidenceIDs...)
			break
		}
	}
	for _, evidenceID := range evidenceIDs {
		for _, record := range s.evidenceRows {
			if record.ID != evidenceID || record.EvidenceType != "raw_response" || record.IntegrityStatus != "verified" || record.SizeBytes > 1<<16 {
				continue
			}
			return s.evidence.Read(record.StorageKey)
		}
	}
	return nil, nil
}

func hypothesisKey(item identity.Hypothesis) string {
	parts := []string{item.EndpointID.String(), item.ObservationPointID.String(), item.ServiceType, item.RawProductName, item.RawVersion}
	for _, observationID := range item.SupportingObservationIDs {
		parts = append(parts, observationID.String())
	}
	return strings.Join(parts, "|")
}

func (s *Service) verifiedEvidence(observationIDs []id.ID) []id.ID {
	verified := map[id.ID]struct{}{}
	for _, row := range s.evidenceRows {
		if row.IntegrityStatus == "verified" {
			verified[row.ID] = struct{}{}
		}
	}
	var out []id.ID
	seen := map[id.ID]struct{}{}
	for _, observationID := range observationIDs {
		for _, item := range s.observations {
			if item.ID != observationID {
				continue
			}
			for _, evidenceID := range item.EvidenceIDs {
				if _, ok := verified[evidenceID]; !ok {
					continue
				}
				if _, ok := seen[evidenceID]; ok {
					continue
				}
				seen[evidenceID] = struct{}{}
				out = append(out, evidenceID)
			}
		}
	}
	return out
}

// mergeFinding 合并同对象上的同一风险。severity 为空时保持空白，不用固定等级代替缺失的情报严重性。
// mergeFinding merges the same risk on one object. An empty severity stays empty and does not substitute a fixed level for missing intelligence severity.
func (s *Service) mergeFinding(endpointID, assetID id.ID, vulnerabilityID string, detectionID, assessmentRunID id.ID, version, findingType, severity string, evidenceIDs []id.ID, ruleID, productID id.ID) {
	subject := endpointID
	if subject.IsZero() {
		subject = assetID
	}
	key := subject.String() + "|" + vulnerabilityID
	now := s.now()
	finding, ok := s.findings[key]
	if !ok {
		finding = &Finding{
			ID: id.MustNew(), FindingKey: key, FindingType: findingType, AssetID: assetID, EndpointID: endpointID,
			ProductID: productID, RuleID: ruleID, VulnerabilityID: vulnerabilityID,
			Title: vulnerabilityID, Severity: severity, Status: "open", FirstSeenAt: now, LastSeenAt: now,
		}
		s.findings[key] = finding
	} else {
		finding.LastSeenAt = now
		if finding.Severity == "" {
			finding.Severity = severity
		}
		if finding.RuleID.IsZero() {
			finding.RuleID = ruleID
		}
		if finding.ProductID.IsZero() {
			finding.ProductID = productID
		}
	}
	occurrenceID := id.MustNew()
	s.occurrences = append(s.occurrences, Occurrence{
		ID: occurrenceID, FindingID: finding.ID, AssessmentRunID: assessmentRunID, DetectionID: detectionID, ObservedAt: now, Severity: severity,
		EvidenceIDs: append([]id.ID(nil), evidenceIDs...), ConditionDigest: digestOf(version + "|" + vulnerabilityID),
	})
	finding.LastOccurrenceID = occurrenceID
	s.projectFinding(finding, now)
}

func (s *Service) appendObservation(item Observation) (Observation, bool) {
	if item.ID.IsZero() {
		item.ID = id.MustNew()
	}
	if item.SourceIdentity == "" && !s.worker.ID.IsZero() {
		item.SourceIdentity = s.worker.ID.String()
	}
	item.ContentDigest = digestOf(struct {
		Type   string
		Status string
		Value  map[string]any
	}{item.Type, item.ResultStatus, item.Value})
	key := item.ScanRunID.String() + "|" + item.ScanUnitID.String() + "|" + s.stageKey(item.ScanRunID, item.ScanUnitID) + "|" + item.Type + "|" + item.SubjectKey + "|" + item.ContentDigest
	if existing, ok := s.idempotency[key]; ok {
		for _, saved := range s.observations {
			if saved.ID == existing {
				return saved, false
			}
		}
	}
	s.idempotency[key] = item.ID
	s.observations = append(s.observations, item)
	return item, true
}

func (s *Service) stageKey(runID, unitID id.ID) string {
	if runID.IsZero() || unitID.IsZero() {
		return ""
	}
	_, units, err := s.tasks.Snapshot(runID)
	if err != nil {
		return ""
	}
	for _, unit := range units {
		if unit.ID == unitID {
			return unit.StageKey
		}
	}
	return ""
}

// dialer 在每次拨号前续租，并按计划快照复核最终地址。
// dialer renews the lease before each dial and rechecks the final address against the plan snapshot.
//
// 计划快照里来自已授权域名的地址会带上主机名和 ResolvedFromGrant。不在快照中的地址不能沿用域名授权。
// An address in the plan snapshot that came from an authorized hostname carries that hostname and ResolvedFromGrant. An address outside the snapshot cannot reuse the hostname grant.
func (s *Service) dialer(lease task.Lease, account *scope.Account) probesdk.Dialer {
	return probesdk.Dialer{Auth: authFunc(func(ctx context.Context, ip netip.Addr, port int, transport, operation string) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := s.commitState(ctx, func() error {
			return s.tasks.Renew(lease, s.now())
		}); err != nil {
			return err
		}
		run, _, err := s.tasks.Snapshot(lease.RunID)
		if err != nil {
			return err
		}
		if run.Status == task.RunCancelling || run.Status == task.RunCancelled {
			return context.Canceled
		}
		grant, ok := s.frozen[lease.RunID]
		if !ok {
			return fmt.Errorf("grant snapshot missing")
		}
		live, ok := s.grants[grant.ID]
		if !ok {
			grant.Status = scope.StatusRevoked
		} else if live.Status != scope.StatusActive {
			grant.Status = live.Status
		}
		if live.Status == scope.StatusActive && live.ValidUntil != nil && !s.now().UTC().Before(live.ValidUntil.UTC()) {
			grant.Status = scope.StatusExpired
		}
		hostname, resolved := s.plannedResolution(lease.RunID, ip)
		decision := grant.Check(scope.CheckInput{
			IP: ip, Hostname: hostname, ResolvedFromGrant: resolved, Port: port, Transport: transport, Operation: operation,
			ObservationPointID: s.pointID, Now: s.now(),
		})
		if !decision.Allowed {
			return fmt.Errorf("%s", decision.Code)
		}
		return nil
	}), Budget: account, Timeout: s.DialTimeout, Now: s.now, PersistBudget: func(ctx context.Context) error {
		return s.persistBudget(ctx, lease.RunID)
	}}
}

// plannedResolution 返回计划快照中该地址对应的已授权主机名。
// plannedResolution returns the authorized hostname recorded for this address in the plan snapshot.
//
// 地址不在 allowed_addresses 中时，第二个返回值为 false。调用方此时不得把域名授权套用到这个地址。
// The second result is false when the address is not in allowed_addresses. The caller must not apply the hostname grant to that address.
func (s *Service) plannedResolution(runID id.ID, ip netip.Addr) (string, bool) {
	run, _, err := s.tasks.Snapshot(runID)
	if err != nil || len(run.Plan) == 0 {
		return "", false
	}
	var plan planBody
	if err := json.Unmarshal(run.Plan, &plan); err != nil || plan.Hostname == "" {
		return "", false
	}
	for _, raw := range plan.Allowed {
		allowed, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		if allowed.Unmap() == ip.Unmap() {
			return plan.Hostname, true
		}
	}
	return "", false
}

// portScanDependency 报告主机发现是否应汇总同地址端口扫描的结果。
// portScanDependency reports whether host discovery should summarize the port scan for the same address.
//
// 授权同时包含 connect 时，发现单元依赖端口扫描，不再对同一端口发起第二次连接。
// When the grant also contains connect, the discovery unit depends on the port scan and does not open a second connection to the same port.
func (s *Service) portScanDependency(lease task.Lease) (id.ID, bool) {
	_, units, err := s.tasks.Snapshot(lease.RunID)
	if err != nil {
		return id.ID{}, false
	}
	byID := map[id.ID]task.Unit{}
	var self task.Unit
	found := false
	for _, unit := range units {
		byID[unit.ID] = unit
		if unit.ID == lease.UnitID {
			self = unit
			found = true
		}
	}
	if !found {
		return id.ID{}, false
	}
	for _, dep := range self.DependsOn {
		parent, ok := byID[dep]
		if ok && parent.UnitType == "port_scan" {
			return parent.ID, true
		}
	}
	return id.ID{}, false
}

func (s *Service) observedReachability(portUnit id.ID, addr netip.Addr) string {
	var results []tcp.Result
	for _, item := range s.observations {
		if item.ScanUnitID != portUnit || item.Type != "port_state" || textOf(item.Value["address"]) != addr.String() {
			continue
		}
		state := textOf(item.Value["state"])
		if state == "" {
			continue
		}
		results = append(results, tcp.Result{State: state})
	}
	return tcp.Reachability(results)
}

// finishSummarizedDiscovery 记录端口扫描已经产生的 TCP 可达性。TCP 没有证明可达时再发送 ARP 或 ICMP，不对同一端口再次连接。
// finishSummarizedDiscovery records the TCP reachability already produced by the port scan. When TCP has not proved reachability, it sends ARP or ICMP and does not connect to the same port again.
func (s *Service) finishSummarizedDiscovery(ctx context.Context, lease task.Lease, account *scope.Account, addr netip.Addr, tcpState string) error {
	arpState := ""
	icmpState := ""
	if tcpState != "reachable" {
		var err error
		arpState, icmpState, err = s.probeLink(ctx, lease, account, addr)
		if err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commitState(ctx, func() error {
		s.recordReachability(lease, addr, "tcp_connect", tcpState)
		if arpState != "" {
			s.recordReachability(lease, addr, "arp", arpState)
		}
		if icmpState != "" {
			s.recordReachability(lease, addr, "icmp", icmpState)
		}
		return nil
	})
}

// finishDirectDiscovery 在没有端口扫描时选择 ARP、ICMP 或 TCP。前一种方法已经给出网络结论时，不再改用后一种方法。
// finishDirectDiscovery selects ARP, ICMP, or TCP when there is no port scan. Once an earlier method has produced a network conclusion, a later method is not used.
func (s *Service) finishDirectDiscovery(ctx context.Context, lease task.Lease, account *scope.Account, addr netip.Addr, ports []int, concurrency int) error {
	arpState, icmpState, err := s.probeLink(ctx, lease, account, addr)
	if err != nil {
		return err
	}
	var tcpState string
	if !networkConclusion(arpState) && !networkConclusion(icmpState) {
		results := tcp.Scan(ctx, s.dialer(lease, account), addr, ports, concurrency, scope.OpDiscovery, s.now)
		tcpState = tcp.Reachability(results)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commitState(ctx, func() error {
		if arpState != "" {
			s.recordReachability(lease, addr, "arp", arpState)
		}
		if icmpState != "" {
			s.recordReachability(lease, addr, "icmp", icmpState)
		}
		if tcpState != "" {
			s.recordReachability(lease, addr, "tcp_connect", tcpState)
		}
		return nil
	})
}

// probeLink 先尝试 ARP。ARP 没有给出网络结论时再发送一条 ICMP Echo。
// probeLink tries ARP first. It sends one ICMP Echo when ARP has not produced a network conclusion.
func (s *Service) probeLink(ctx context.Context, lease task.Lease, account *scope.Account, addr netip.Addr) (string, string, error) {
	beforeSend := s.beforeDiscoverySend(ctx, lease, account)
	arpState, err := arpprobe.Probe(ctx, addr, s.DialTimeout, beforeSend)
	if err != nil {
		return "", "", err
	}
	if networkConclusion(arpState) {
		return arpState, "", nil
	}
	icmpState, err := icmpprobe.Echo(ctx, addr, s.DialTimeout, beforeSend)
	if err != nil {
		return "", "", err
	}
	return arpState, icmpState, nil
}

func (s *Service) beforeDiscoverySend(ctx context.Context, lease task.Lease, account *scope.Account) func() error {
	return func() error {
		if err := func() error {
			s.mu.Lock()
			defer s.mu.Unlock()
			if err := s.commitState(ctx, func() error {
				return s.tasks.Renew(lease, s.now())
			}); err != nil {
				return err
			}
			run, _, err := s.tasks.Snapshot(lease.RunID)
			if err != nil {
				return err
			}
			if run.Status == task.RunCancelling || run.Status == task.RunCancelled {
				return context.Canceled
			}
			return account.AcquireRequest(ctx, s.now())
		}(); err != nil {
			return err
		}
		if err := s.persistBudget(ctx, lease.RunID); err != nil {
			account.ReleaseReservation(false)
			return err
		}
		return nil
	}
}

// persistBudget 把当前预算计数写入扫描运行。没有数据库时不写。
// persistBudget writes the current budget counters onto the scan run. It writes nothing when there is no database.
//
// 写入使用单调合并：较新的较小计数不能把已经记下的连接、请求或证据字节改小。调用方在网络操作开始前调用它。
// The write merges monotonically. A newer smaller counter cannot reduce a connection, request, or evidence count that was already recorded. The caller invokes it before a network operation starts.
func (s *Service) persistBudget(ctx context.Context, runID id.ID) error {
	if s.db == nil {
		return nil
	}
	s.mu.Lock()
	account := s.accounts[runID]
	s.mu.Unlock()
	if account == nil {
		return fmt.Errorf("persist budget %s: ledger missing", runID)
	}
	return s.db.persistBudget(ctx, runID, account.ExportUsage())
}

func networkConclusion(state string) bool {
	switch state {
	case "reachable", "no_response", "unreachable", "error":
		return true
	default:
		return false
	}
}

func (s *Service) recordReachability(lease task.Lease, addr netip.Addr, method, state string) {
	s.appendObservation(Observation{
		ScanRunID: lease.RunID, ScanUnitID: lease.UnitID, StageAttemptID: lease.AttemptID,
		ObservationPointID: lease.ObservationPointID, Type: "host_reachability", SubjectKey: "ip:" + addr.String() + ":" + method,
		ObservedAt: s.now(), CollectedAt: s.now(), ResultStatus: reachStatus(state),
		ValueSchemaVersion: "1", Value: map[string]any{"method": method, "state": state, "address": addr.String()},
		SourceKind: "network",
	})
}

func textOf(value any) string {
	text, _ := value.(string)
	return text
}

type authFunc func(context.Context, netip.Addr, int, string, string) error

func (f authFunc) Authorize(ctx context.Context, ip netip.Addr, port int, transport, operation string) error {
	return f(ctx, ip, port, transport, operation)
}

// evidenceContent 返回已存储字节的真实类型和编码。文件按原始字节发布，因此编码是 identity。
// evidenceContent returns the actual type and encoding of the stored bytes. Files are published as raw bytes, so the encoding is identity.
func evidenceContent(protocol string) (string, string) {
	switch protocol {
	case "http":
		return "application/http", "identity"
	case "tls":
		return "application/pkix-cert", "identity"
	case "ssh", "ftp", "smtp":
		return "text/plain", "identity"
	case "dns":
		return "application/dns-message", "identity"
	case "mysql", "postgresql", "mongodb", "tds", "tns", "cql", "bolt", "clickhouse":
		return "application/octet-stream", "identity"
	case "redis", "memcached":
		return "text/plain", "identity"
	default:
		return "", "identity"
	}
}

// observationStatusForCollection 把采集状态映射到观察结果状态。采集状态本身写入 value.collection_status。
// observationStatusForCollection maps a collection status onto an observation result status. The collection status itself is stored in value.collection_status.
func observationStatusForCollection(status string) string {
	switch status {
	case collect.StatusCollected, collect.StatusEmpty:
		return "observed"
	case collect.StatusUnsupported:
		return "unsupported"
	case collect.StatusNotRequested:
		return "not_scanned"
	default:
		return "error"
	}
}

func reachStatus(state string) string {
	switch state {
	case "reachable":
		return "observed"
	case "no_response":
		return "no_response"
	case "unreachable":
		return "unreachable"
	case "error":
		return "error"
	case "unsupported":
		return "unsupported"
	default:
		return "not_scanned"
	}
}

func portResultStatus(state string) string {
	switch state {
	case "open", "closed":
		return "observed"
	case "no_response":
		return "no_response"
	case "unreachable":
		return "unreachable"
	case "unsupported":
		return "unsupported"
	case "not_scanned":
		return "not_scanned"
	default:
		return "error"
	}
}

func endpointState(state string) string {
	switch state {
	case "open", "closed", "no_response", "unreachable":
		return state
	default:
		return "unknown"
	}
}

func mapApplicability(value string) string {
	switch value {
	case assess.Affected:
		return "confirmed"
	case assess.NotAffected:
		return "not_vulnerable"
	case assess.InsufficientEvidence:
		return "insufficient_evidence"
	default:
		return "unknown"
	}
}
