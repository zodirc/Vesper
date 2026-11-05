package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/internal/task"
	"github.com/zodirc/Vesper/internal/zgrab2"
	"github.com/zodirc/Vesper/pkg/probesdk"
)

type zgrabInput struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Hostname string `json:"hostname"`
}

// scheduleZGrab 为开放的 TCP 端口追加一次 ZGrab2 抓取。自研协议探针仍按原单元执行。
// scheduleZGrab appends one ZGrab2 grab for an open TCP port. The native protocol probes still run as their own units.
func (s *Service) scheduleZGrab(lease task.Lease, addr netip.Addr, port int, hostname string) error {
	payload, err := json.Marshal(zgrabInput{Address: addr.String(), Port: port, Hostname: hostname})
	if err != nil {
		return err
	}
	unit := task.Unit{
		ScanRunID: lease.RunID, TargetID: lease.TargetID, ObservationPointID: lease.ObservationPointID,
		UnitType: "zgrab2", StageKey: fmt.Sprintf("zgrab2:%s:%d", addr.String(), port),
		DependsOn: []id.ID{lease.UnitID}, RequiredCapabilities: []string{"zgrab2"}, Input: payload, Priority: 4, CreatedAt: s.now(),
	}
	if err := s.tasks.AddUnit(unit); err != nil && !errors.Is(err, task.ErrDuplicateStage) {
		return err
	}
	return nil
}

func (s *Service) executeZGrab(ctx context.Context, lease task.Lease, account *scope.Account) error {
	var input zgrabInput
	if err := json.Unmarshal(lease.Input, &input); err != nil {
		return err
	}
	addr, err := netip.ParseAddr(input.Address)
	if err != nil {
		return err
	}
	if err := s.authorizeZGrab(ctx, lease, addr, input.Port, input.Hostname); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return s.finishZGrab(ctx, lease, addr, input.Port, input.Hostname, "not_scanned", nil, map[string]any{"reason": err.Error()})
	}
	if _, err := zgrab2.Binary(); err != nil {
		return s.finishZGrab(ctx, lease, addr, input.Port, input.Hostname, "unsupported", nil, map[string]any{"reason": "executor_missing"})
	}
	reserved, err := s.reserveZGrab(ctx, lease, account)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			s.releaseZGrab(account, reserved)
			return err
		}
		var budget *scope.BudgetError
		if errors.As(err, &budget) {
			s.releaseZGrab(account, reserved)
			return s.finishZGrab(ctx, lease, addr, input.Port, input.Hostname, "not_scanned", nil, map[string]any{"reason": err.Error()})
		}
		s.releaseZGrab(account, reserved)
		return err
	}
	report, raw, runErr := zgrab2.Run(ctx, addr, input.Port, input.Hostname)
	if runErr != nil && (errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded)) {
		return runErr
	}
	value := map[string]any{"modules": []string{"http", "tls"}}
	status := "error"
	if runErr == nil {
		status = zgrab2.ResultStatus(report.Modules)
		statuses := map[string]string{}
		for _, module := range report.Modules {
			statuses[module.Name] = module.Status
			if module.HTTPStatus > 0 {
				value["http_status"] = module.HTTPStatus
			}
			if module.TLSVersion != "" {
				value["tls_version"] = module.TLSVersion
			}
		}
		value["statuses"] = statuses
	} else {
		value["reason"] = runErr.Error()
	}
	return s.finishZGrab(ctx, lease, addr, input.Port, input.Hostname, status, raw, value)
}

func (s *Service) authorizeZGrab(ctx context.Context, lease task.Lease, addr netip.Addr, port int, hostname string) error {
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
	planned, resolved := s.plannedResolution(lease.RunID, addr)
	if planned != "" {
		hostname = planned
	}
	decision := grant.Check(scope.CheckInput{
		IP: addr, Hostname: hostname, ResolvedFromGrant: resolved, Port: port, Transport: "tcp", Operation: scope.OpProtocolProbe,
		ObservationPointID: lease.ObservationPointID, Now: s.now(),
	})
	if !decision.Allowed {
		return fmt.Errorf("%s", decision.Code)
	}
	return nil
}

func (s *Service) reserveZGrab(ctx context.Context, lease task.Lease, account *scope.Account) (int, error) {
	for i := 0; i < zgrab2.ModuleCount(); i++ {
		if err := s.reserveOneZGrab(ctx, lease, account, true); err != nil {
			return i, err
		}
		if err := s.reserveOneZGrab(ctx, lease, account, false); err != nil {
			account.ReleaseReservation(true)
			return i, err
		}
	}
	if err := s.persistBudget(ctx, lease.RunID); err != nil {
		return zgrab2.ModuleCount(), err
	}
	return zgrab2.ModuleCount(), nil
}

func (s *Service) reserveOneZGrab(ctx context.Context, lease task.Lease, account *scope.Account, connection bool) error {
	s.mu.Lock()
	err := s.commitState(ctx, func() error {
		return s.tasks.Renew(lease, s.now())
	})
	run, _, snapErr := s.tasks.Snapshot(lease.RunID)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if snapErr != nil {
		return snapErr
	}
	if run.Status == task.RunCancelling || run.Status == task.RunCancelled {
		return context.Canceled
	}
	if connection {
		return account.AcquireConnection(ctx, s.now())
	}
	return account.AcquireRequest(ctx, s.now())
}

func (s *Service) releaseZGrab(account *scope.Account, count int) {
	for i := 0; i < count; i++ {
		account.ReleaseReservation(true)
		account.ReleaseReservation(false)
	}
}

func (s *Service) finishZGrab(ctx context.Context, lease task.Lease, addr netip.Addr, port int, hostname, status string, raw []byte, value map[string]any) error {
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
		record = &EvidenceRecord{
			ID: evidenceID, EvidenceType: "tool_output", StorageKey: object.StorageKey, SizeBytes: object.SizeBytes,
			DigestAlgorithm: object.DigestAlgorithm, ContentDigest: object.ContentDigest, ContentType: "application/x-ndjson",
			ContentEncoding: "identity", SourceModule: "zgrab2", SourceAttemptID: lease.AttemptID, IntegrityStatus: "verified",
			Sensitivity: "internal", CapturedAt: storedAt, StoredAt: &storedAt,
		}
		evidenceIDs = []id.ID{evidenceID}
		value["evidence_digest"] = record.ContentDigest
	}
	if value == nil {
		value = map[string]any{}
	}
	value["executor"] = "zgrab2"
	value["address"] = addr.String()
	value["connected_address"] = addr.String()
	value["port"] = port
	value["transport"] = "tcp"
	if hostname != "" {
		value["hostname"] = hostname
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if record != nil {
		s.evidenceRows = append(s.evidenceRows, *record)
	}
	endpoint := s.catalog.ObserveEndpoint(addr, "tcp", port, "open", s.now())
	endpointID := endpoint.ID
	s.appendObservation(Observation{
		ScanRunID: lease.RunID, ScanUnitID: lease.UnitID, StageAttemptID: lease.AttemptID, EndpointID: &endpointID,
		ObservationPointID: lease.ObservationPointID, Type: "zgrab2", SubjectKey: fmt.Sprintf("zgrab2:%s:%d", addr.String(), port),
		ObservedAt: s.now(), CollectedAt: s.now(), ResultStatus: status, ValueSchemaVersion: "1", Value: value,
		EvidenceIDs: evidenceIDs, SourceKind: "network",
	})
	return s.flush(ctx)
}
