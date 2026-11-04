package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/zodirc/Vesper/internal/assess"
	"github.com/zodirc/Vesper/internal/asset"
	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/identity"
	"github.com/zodirc/Vesper/internal/intel"
	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/internal/task"
)

type budgetRow struct {
	targets, addresses, connections, requests, evidence int64
	started, next                                       time.Time
}

func (d *pgStore) load(ctx context.Context, s *Service) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin task load: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var points int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM observation_point`).Scan(&points); err != nil {
		return fmt.Errorf("count observation points: %w", err)
	}
	if points == 0 {
		if err := saveNode(ctx, tx, s); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	pointID, worker, err := loadNode(ctx, tx)
	if err != nil {
		return err
	}
	grants, err := loadGrants(ctx, tx)
	if err != nil {
		return err
	}
	revisions, err := loadRevisions(ctx, tx)
	if err != nil {
		return err
	}
	targets, assets, endpoints, err := loadCatalog(ctx, tx)
	if err != nil {
		return err
	}
	runs, units, attempts, snapshots, budgets, err := loadTasks(ctx, tx)
	if err != nil {
		return err
	}
	evidenceRows, err := loadEvidence(ctx, tx)
	if err != nil {
		return err
	}
	observations, idempotency, err := loadObservations(ctx, tx)
	if err != nil {
		return err
	}
	products, aliases, err := loadProducts(ctx, tx)
	if err != nil {
		return err
	}
	statements, err := loadStatements(ctx, tx)
	if err != nil {
		return err
	}
	intelSnapshots, err := loadIntelSnapshots(ctx, tx)
	if err != nil {
		return err
	}
	if len(intelSnapshots) == 0 && len(statements) > 0 {
		published, err := backfillSnapshot(statements, s.now().UTC())
		if err != nil {
			return err
		}
		if err := insertSnapshot(ctx, tx, published); err != nil {
			return err
		}
		intelSnapshots = []IntelSnapshot{published}
	}
	hypotheses, err := loadHypotheses(ctx, tx)
	if err != nil {
		return err
	}
	detections, err := loadDetections(ctx, tx)
	if err != nil {
		return err
	}
	findings, occurrences, err := loadFindings(ctx, tx)
	if err != nil {
		return err
	}
	dispositions, err := loadDispositions(ctx, tx)
	if err != nil {
		return err
	}
	loadedPacks, err := loadPacks(ctx, tx)
	if err != nil {
		return err
	}
	if len(loadedPacks) == 0 {
		if err := savePacks(ctx, tx, s); err != nil {
			return err
		}
		loadedPacks = s.packs
	}
	var location *string
	if err := tx.QueryRow(ctx, `SELECT location_label FROM observation_point WHERE name = 'local'`).Scan(&location); err != nil {
		return fmt.Errorf("load observation point label: %w", err)
	}
	active, err := loadActiveTemplates(ctx, tx)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit task load: %w", err)
	}
	s.pointID = pointID
	if location != nil {
		s.locationLabel = *location
	}
	s.worker = worker
	if s.worker.Capabilities == nil {
		s.worker.Capabilities = map[string]struct{}{}
	}
	s.worker.Capabilities["active_detection"] = struct{}{}
	s.grants = grants
	s.revisions = revisions
	s.catalog.Reset(targets, endpoints, assets)
	s.tasks.Replace(runs, units, attempts)
	s.evidenceRows = evidenceRows
	s.observations = observations
	s.idempotency = idempotency
	s.products = products
	s.aliases = aliases
	s.statements = statements
	s.snapshots = intelSnapshots
	s.hypotheses = hypotheses
	s.detections = detections
	s.findings = findings
	s.occurrences = occurrences
	s.dispositions = dispositions
	s.packs = loadedPacks
	s.active = active
	s.frozen = map[id.ID]scope.Grant{}
	s.accounts = map[id.ID]*scope.Account{}
	s.baselines = map[id.ID]scope.Usage{}
	for _, run := range runs {
		grant, err := decodeGrant(snapshots[run.ID])
		if err != nil {
			return fmt.Errorf("load scan run %s: %w", run.ID, err)
		}
		s.frozen[run.ID] = grant
		started := run.CreatedAt
		usage := budgets[run.ID]
		if !usage.started.IsZero() {
			started = usage.started
		}
		account := scope.NewAccount(scope.FromGrant(grant), started)
		account.RestoreUsage(scope.Usage{
			Started: started, Targets: usage.targets, Addresses: usage.addresses, Connections: usage.connections,
			Requests: usage.requests, Evidence: usage.evidence, NextAllowed: usage.next,
		})
		s.accounts[run.ID] = account
	}
	return nil
}

// reloadTaskAuthority 在当前事务中锁定授权和任务行，再装入这些行。
// reloadTaskAuthority locks grant and task rows in the current transaction, then loads those rows.
//
// 调用方必须已经持有服务锁。账本对象在本地计数不低于数据库计数时保持原指针，避免执行中的拨号丢失增量。
// The caller must already hold the service lock. The budget object keeps its pointer when local counters are at least the database counters, so an in-flight dial does not lose increments.
func (d *pgStore) reloadTaskAuthority(ctx context.Context, tx pgx.Tx, s *Service) error {
	if _, err := tx.Exec(ctx, `SELECT id FROM scope_grant ORDER BY id FOR UPDATE`); err != nil {
		return fmt.Errorf("lock scope grants: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT id FROM scan_run ORDER BY id FOR UPDATE`); err != nil {
		return fmt.Errorf("lock scan runs: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT id FROM scan_unit ORDER BY id FOR UPDATE`); err != nil {
		return fmt.Errorf("lock scan units: %w", err)
	}
	grants, err := loadGrants(ctx, tx)
	if err != nil {
		return err
	}
	revisions, err := loadRevisions(ctx, tx)
	if err != nil {
		return err
	}
	runs, units, attempts, snapshots, budgets, err := loadTasks(ctx, tx)
	if err != nil {
		return err
	}
	frozen := map[id.ID]scope.Grant{}
	accounts := map[id.ID]*scope.Account{}
	for _, run := range runs {
		grant, err := decodeGrant(snapshots[run.ID])
		if err != nil {
			return fmt.Errorf("load scan run %s: %w", run.ID, err)
		}
		frozen[run.ID] = grant
		started := run.CreatedAt
		row := budgets[run.ID]
		if !row.started.IsZero() {
			started = row.started
		}
		stored := scope.Usage{
			Started: started, Targets: row.targets, Addresses: row.addresses, Connections: row.connections,
			Requests: row.requests, Evidence: row.evidence, NextAllowed: row.next,
		}
		account := s.accounts[run.ID]
		if account == nil {
			account = scope.NewAccount(scope.FromGrant(grant), started)
			account.RestoreUsage(stored)
		} else if !usageCovers(account.ExportUsage(), stored) {
			account.RestoreUsage(mergeUsage(account.ExportUsage(), stored))
		}
		accounts[run.ID] = account
	}
	s.grants = grants
	s.revisions = revisions
	s.tasks.Replace(runs, units, attempts)
	s.frozen = frozen
	s.accounts = accounts
	return nil
}

func usageCovers(live, stored scope.Usage) bool {
	return live.Targets >= stored.Targets && live.Addresses >= stored.Addresses && live.Connections >= stored.Connections && live.Requests >= stored.Requests && live.Evidence >= stored.Evidence
}

func mergeUsage(live, stored scope.Usage) scope.Usage {
	out := stored
	if live.Targets > out.Targets {
		out.Targets = live.Targets
	}
	if live.Addresses > out.Addresses {
		out.Addresses = live.Addresses
	}
	if live.Connections > out.Connections {
		out.Connections = live.Connections
	}
	if live.Requests > out.Requests {
		out.Requests = live.Requests
	}
	if live.Evidence > out.Evidence {
		out.Evidence = live.Evidence
	}
	if !live.Started.IsZero() {
		out.Started = live.Started
	}
	if live.NextAllowed.After(out.NextAllowed) {
		out.NextAllowed = live.NextAllowed
	}
	return out
}

func loadNode(ctx context.Context, tx pgx.Tx) (id.ID, task.Worker, error) {
	var pointText, workerText, status string
	var capsRaw []byte
	if err := tx.QueryRow(ctx, `SELECT id::text FROM observation_point WHERE name = 'local'`).Scan(&pointText); err != nil {
		return id.ID{}, task.Worker{}, fmt.Errorf("load local observation point: %w", err)
	}
	if err := tx.QueryRow(ctx, `SELECT id::text, status, capabilities FROM worker WHERE name = 'local'`).Scan(&workerText, &status, &capsRaw); err != nil {
		return id.ID{}, task.Worker{}, fmt.Errorf("load local worker: %w", err)
	}
	pointID, err := id.Parse(pointText)
	if err != nil {
		return id.ID{}, task.Worker{}, err
	}
	workerID, err := id.Parse(workerText)
	if err != nil {
		return id.ID{}, task.Worker{}, err
	}
	var names []string
	if err := json.Unmarshal(capsRaw, &names); err != nil {
		return id.ID{}, task.Worker{}, fmt.Errorf("decode worker capabilities: %w", err)
	}
	caps := map[string]struct{}{}
	for _, name := range names {
		caps[name] = struct{}{}
	}
	return pointID, task.Worker{ID: workerID, ObservationPointID: pointID, Status: status, Capabilities: caps}, nil
}

func loadGrants(ctx context.Context, tx pgx.Tx) (map[id.ID]scope.Grant, error) {
	rows, err := tx.Query(ctx, `
SELECT id::text, name, subject_type, subject_id::text, target_selectors, allowed_transports::text[], allowed_ports,
       allowed_operations::text[], observation_point_ids::text[], valid_from, valid_until, max_targets, max_addresses,
       max_connections, max_requests, max_concurrency, max_rate_per_second, max_runtime_seconds, max_evidence_bytes,
       status, approved_by::text, approved_at, revoked_at, revocation_reason, created_at
FROM scope_grant`)
	if err != nil {
		return nil, fmt.Errorf("load grants: %w", err)
	}
	defer rows.Close()
	out := map[id.ID]scope.Grant{}
	for rows.Next() {
		var grant scope.Grant
		var idText string
		var subject, approved *string
		var selectors, ports []byte
		var transports, operations, points []string
		var validUntil, approvedAt, revokedAt *time.Time
		var runtimeSeconds int64
		var reason *string
		if err := rows.Scan(&idText, &grant.Name, &grant.SubjectType, &subject, &selectors, &transports, &ports, &operations, &points,
			&grant.ValidFrom, &validUntil, &grant.MaxTargets, &grant.MaxAddresses, &grant.MaxConnections, &grant.MaxRequests,
			&grant.MaxConcurrency, &grant.MaxRatePerSecond, &runtimeSeconds, &grant.MaxEvidenceBytes, &grant.Status, &approved,
			&approvedAt, &revokedAt, &reason, &grant.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan grant: %w", err)
		}
		grant.ID, err = id.Parse(idText)
		if err != nil {
			return nil, err
		}
		grant.SubjectID, err = parseOptionalID(subject)
		if err != nil {
			return nil, err
		}
		grant.ApprovedBy, err = parseOptionalID(approved)
		if err != nil {
			return nil, err
		}
		var selectorDocs []scope.Selector
		if err := json.Unmarshal(selectors, &selectorDocs); err != nil {
			return nil, fmt.Errorf("decode grant selectors: %w", err)
		}
		for _, item := range selectorDocs {
			parsed, err := scope.ParseSelector(item.Kind, item.Value)
			if err != nil {
				return nil, err
			}
			grant.Selectors = append(grant.Selectors, parsed)
		}
		if err := json.Unmarshal(ports, &grant.Ports); err != nil {
			return nil, fmt.Errorf("decode grant ports: %w", err)
		}
		grant.AllowedTransports = transports
		grant.AllowedOperations = operations
		grant.ObservationPointIDs, err = parseIDs(points)
		if err != nil {
			return nil, err
		}
		grant.ValidUntil = validUntil
		grant.ApprovedAt = approvedAt
		grant.RevokedAt = revokedAt
		if reason != nil {
			grant.RevocationReason = *reason
		}
		grant.MaxRuntime = time.Duration(runtimeSeconds) * time.Second
		grant.ValidFrom = grant.ValidFrom.UTC()
		grant.CreatedAt = grant.CreatedAt.UTC()
		out[grant.ID] = grant
	}
	return out, rows.Err()
}

func loadRevisions(ctx context.Context, tx pgx.Tx) ([]Revision, error) {
	rows, err := tx.Query(ctx, `SELECT id::text, grant_id::text, action, actor_id::text, content, created_at FROM scope_grant_revision ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("load grant revisions: %w", err)
	}
	defer rows.Close()
	var out []Revision
	for rows.Next() {
		var item Revision
		var idText, grantText string
		var actor *string
		if err := rows.Scan(&idText, &grantText, &item.Action, &actor, &item.Content, &item.At); err != nil {
			return nil, err
		}
		item.ID, err = id.Parse(idText)
		if err != nil {
			return nil, err
		}
		item.GrantID, err = id.Parse(grantText)
		if err != nil {
			return nil, err
		}
		parsed, err := parseOptionalID(actor)
		if err != nil {
			return nil, err
		}
		if parsed != nil {
			item.ActorID = *parsed
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func loadCatalog(ctx context.Context, tx pgx.Tx) ([]asset.Target, []asset.Asset, []asset.Endpoint, error) {
	rows, err := tx.Query(ctx, `
SELECT id::text, target_type, raw_value, normalized_value, address::text, network::text, hostname_ascii, port, transport, created_at
FROM scan_target`)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load targets: %w", err)
	}
	defer rows.Close()
	var targets []asset.Target
	for rows.Next() {
		var item asset.Target
		var idText string
		var address, network, hostname, transport *string
		if err := rows.Scan(&idText, &item.TargetType, &item.RawValue, &item.NormalizedValue, &address, &network, &hostname, &item.Port, &transport, &item.CreatedAt); err != nil {
			return nil, nil, nil, err
		}
		item.ID, err = id.Parse(idText)
		if err != nil {
			return nil, nil, nil, err
		}
		if address != nil {
			parsed, err := parseStoredAddr(*address)
			if err != nil {
				return nil, nil, nil, err
			}
			item.Address = &parsed
		}
		if network != nil {
			parsed, err := netip.ParsePrefix(*network)
			if err != nil {
				return nil, nil, nil, err
			}
			item.Prefix = &parsed
		}
		if hostname != nil {
			item.Hostname = *hostname
		}
		if transport != nil {
			item.Transport = *transport
		}
		targets = append(targets, item)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, nil, err
	}
	rows.Close()
	assetRows, err := tx.Query(ctx, `
SELECT id::text, asset_type, platform_family, platform_name, platform_version, machine_id_hash, identity_confidence::text,
       identity_status, first_observed_at, last_observed_at, created_at, updated_at
FROM asset`)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load assets: %w", err)
	}
	defer assetRows.Close()
	var assets []asset.Asset
	for assetRows.Next() {
		var item asset.Asset
		var idText string
		var family, name, version, machine *string
		if err := assetRows.Scan(&idText, &item.AssetType, &family, &name, &version, &machine, &item.IdentityConfidence, &item.IdentityStatus,
			&item.FirstObservedAt, &item.LastObservedAt, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, nil, nil, err
		}
		item.ID, err = id.Parse(idText)
		if err != nil {
			return nil, nil, nil, err
		}
		item.PlatformFamily = deref(family)
		item.PlatformName = deref(name)
		item.PlatformVersion = deref(version)
		item.MachineIDHash = deref(machine)
		assets = append(assets, item)
	}
	if err := assetRows.Err(); err != nil {
		return nil, nil, nil, err
	}
	endpointRows, err := tx.Query(ctx, `
SELECT id::text, asset_id::text, address::text, transport, port, current_state, state_observed_at, first_observed_at,
       last_observed_at, created_at, updated_at
FROM endpoint`)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load endpoints: %w", err)
	}
	defer endpointRows.Close()
	var endpoints []asset.Endpoint
	for endpointRows.Next() {
		var item asset.Endpoint
		var idText, address string
		var assetText *string
		if err := endpointRows.Scan(&idText, &assetText, &address, &item.Transport, &item.Port, &item.CurrentState, &item.StateObservedAt,
			&item.FirstObservedAt, &item.LastObservedAt, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, nil, nil, err
		}
		item.ID, err = id.Parse(idText)
		if err != nil {
			return nil, nil, nil, err
		}
		item.AssetID, err = parseOptionalID(assetText)
		if err != nil {
			return nil, nil, nil, err
		}
		item.Address, err = parseStoredAddr(address)
		if err != nil {
			return nil, nil, nil, err
		}
		endpoints = append(endpoints, item)
	}
	return targets, assets, endpoints, endpointRows.Err()
}

func loadTasks(ctx context.Context, tx pgx.Tx) ([]task.Run, []task.Unit, []task.Attempt, map[id.ID][]byte, map[id.ID]budgetRow, error) {
	rows, err := tx.Query(ctx, `
SELECT id::text, name, target_ids::text[], scope_grant_id::text, scope_grant_digest, observation_point_ids::text[],
       probe_profile_version, fingerprint_pack_version, rule_pack_version, product_catalog_version, scope_snapshot,
       budget_targets, budget_addresses, budget_connections, budget_requests, budget_evidence, budget_started_at, budget_next_allowed,
       status, progress_total, progress_done, progress_failed, progress_skipped, failure_summary, created_at, started_at, finished_at, cancel_requested_at,
       plan_snapshot, trigger_type, effective_budget, intel_snapshot_id::text
FROM scan_run`)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("load scan runs: %w", err)
	}
	defer rows.Close()
	var runs []task.Run
	snapshots := map[id.ID][]byte{}
	budgets := map[id.ID]budgetRow{}
	for rows.Next() {
		var run task.Run
		var idText, grantText string
		var name, failure *string
		var targets, points []string
		var snapshot []byte
		var budget budgetRow
		var startedBudget, nextBudget *time.Time
		var intelText *string
		if err := rows.Scan(&idText, &name, &targets, &grantText, &run.ScopeDigest, &points, &run.ProbeProfileVersion, &run.FingerprintPackVersion,
			&run.RulePackVersion, &run.ProductCatalogVersion, &snapshot, &budget.targets, &budget.addresses, &budget.connections, &budget.requests,
			&budget.evidence, &startedBudget, &nextBudget, &run.Status, &run.ProgressTotal, &run.ProgressDone, &run.ProgressFailed, &run.ProgressSkipped,
			&failure, &run.CreatedAt, &run.StartedAt, &run.FinishedAt, &run.CancelRequestedAt, &run.Plan, &run.TriggerType, &run.EffectiveBudget, &intelText); err != nil {
			return nil, nil, nil, nil, nil, err
		}
		run.ID, err = id.Parse(idText)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		run.ScopeGrantID, err = id.Parse(grantText)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		run.Name = deref(name)
		run.FailureSummary = deref(failure)
		run.IntelSnapshotID, err = parseIDValue(intelText)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		run.TargetIDs, err = parseIDs(targets)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		run.ObservationPointIDs, err = parseIDs(points)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		if startedBudget != nil {
			budget.started = startedBudget.UTC()
		}
		if nextBudget != nil {
			budget.next = nextBudget.UTC()
		}
		snapshots[run.ID] = append([]byte(nil), snapshot...)
		budgets[run.ID] = budget
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	rows.Close()
	unitRows, err := tx.Query(ctx, `
SELECT id::text, scan_run_id::text, target_id::text, observation_point_id::text, unit_type, stage_key, depends_on_unit_ids::text[],
       required_capabilities::text[], input_snapshot, status, priority, attempt_count, max_attempts, not_before, lease_id::text,
       lease_owner_id::text, lease_expires_at, fencing_token, terminal_reason, result_summary, created_at, updated_at
FROM scan_unit`)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("load scan units: %w", err)
	}
	defer unitRows.Close()
	var units []task.Unit
	for unitRows.Next() {
		var unit task.Unit
		var idText, runText, targetText, pointText string
		var depends, capabilities []string
		var lease, owner, reason *string
		if err := unitRows.Scan(&idText, &runText, &targetText, &pointText, &unit.UnitType, &unit.StageKey, &depends, &capabilities, &unit.Input,
			&unit.Status, &unit.Priority, &unit.AttemptCount, &unit.MaxAttempts, &unit.NotBefore, &lease, &owner, &unit.LeaseExpiresAt,
			&unit.FencingToken, &reason, &unit.ResultSummary, &unit.CreatedAt, &unit.UpdatedAt); err != nil {
			return nil, nil, nil, nil, nil, err
		}
		unit.ID, err = id.Parse(idText)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		unit.ScanRunID, err = id.Parse(runText)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		unit.TargetID, err = id.Parse(targetText)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		unit.ObservationPointID, err = id.Parse(pointText)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		unit.DependsOn, err = parseIDs(depends)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		unit.RequiredCapabilities = capabilities
		unit.LeaseID, err = parseIDValue(lease)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		unit.LeaseOwnerID, err = parseIDValue(owner)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		unit.TerminalReason = deref(reason)
		units = append(units, unit)
	}
	if err := unitRows.Err(); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	attemptRows, err := tx.Query(ctx, `
SELECT id::text, scan_unit_id::text, attempt_no, worker_id::text, lease_id::text, fencing_token, status, started_at, heartbeat_at, finished_at,
       error_code, error_message, resource_usage, result_digest, created_at
FROM stage_attempt`)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("load stage attempts: %w", err)
	}
	defer attemptRows.Close()
	var attempts []task.Attempt
	for attemptRows.Next() {
		var attempt task.Attempt
		var idText, unitText, workerText, leaseText string
		var code, message, digest *string
		if err := attemptRows.Scan(&idText, &unitText, &attempt.AttemptNo, &workerText, &leaseText, &attempt.FencingToken, &attempt.Status,
			&attempt.StartedAt, &attempt.HeartbeatAt, &attempt.FinishedAt, &code, &message, &attempt.ResourceUsage, &digest, &attempt.CreatedAt); err != nil {
			return nil, nil, nil, nil, nil, err
		}
		attempt.ID, err = id.Parse(idText)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		attempt.ScanUnitID, err = id.Parse(unitText)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		attempt.WorkerID, err = id.Parse(workerText)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		attempt.LeaseID, err = id.Parse(leaseText)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		attempt.ErrorCode = deref(code)
		attempt.ErrorMessage = deref(message)
		attempt.ResultDigest = deref(digest)
		attempts = append(attempts, attempt)
	}
	return runs, units, attempts, snapshots, budgets, attemptRows.Err()
}

func loadEvidence(ctx context.Context, tx pgx.Tx) ([]EvidenceRecord, error) {
	rows, err := tx.Query(ctx, `
SELECT id::text, evidence_type, storage_key, content_type, content_encoding, size_bytes, digest_algorithm, content_digest, source_module, source_attempt_id::text,
       integrity_status, sensitivity, captured_at, stored_at
FROM evidence_record`)
	if err != nil {
		return nil, fmt.Errorf("load evidence: %w", err)
	}
	defer rows.Close()
	var out []EvidenceRecord
	for rows.Next() {
		var item EvidenceRecord
		var idText string
		var attempt, contentType, contentEncoding *string
		if err := rows.Scan(&idText, &item.EvidenceType, &item.StorageKey, &contentType, &contentEncoding, &item.SizeBytes, &item.DigestAlgorithm, &item.ContentDigest, &item.SourceModule, &attempt, &item.IntegrityStatus, &item.Sensitivity, &item.CapturedAt, &item.StoredAt); err != nil {
			return nil, err
		}
		item.ID, err = id.Parse(idText)
		if err != nil {
			return nil, err
		}
		item.ContentType = deref(contentType)
		item.ContentEncoding = deref(contentEncoding)
		if attempt != nil && *attempt != "" {
			item.SourceAttemptID, err = id.Parse(*attempt)
			if err != nil {
				return nil, err
			}
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func loadObservations(ctx context.Context, tx pgx.Tx) ([]Observation, map[string]id.ID, error) {
	rows, err := tx.Query(ctx, `
SELECT id::text, scan_run_id::text, scan_unit_id::text, stage_attempt_id::text, asset_id::text, endpoint_id::text, observation_point_id::text,
       observation_type, subject_key, observed_at, collected_at, result_status, value_schema_version, value, evidence_record_ids::text[],
       source_kind, source_identity, content_digest
FROM observation ORDER BY collected_at`)
	if err != nil {
		return nil, nil, fmt.Errorf("load observations: %w", err)
	}
	defer rows.Close()
	var out []Observation
	for rows.Next() {
		var item Observation
		var idText, pointText string
		var runText, unitText, attemptText, assetText, endpointText, sourceIdentity *string
		var value []byte
		var evidence []string
		if err := rows.Scan(&idText, &runText, &unitText, &attemptText, &assetText, &endpointText, &pointText, &item.Type, &item.SubjectKey, &item.ObservedAt,
			&item.CollectedAt, &item.ResultStatus, &item.ValueSchemaVersion, &value, &evidence, &item.SourceKind, &sourceIdentity, &item.ContentDigest); err != nil {
			return nil, nil, err
		}
		item.ID, err = id.Parse(idText)
		if err != nil {
			return nil, nil, err
		}
		item.ScanRunID, err = parseIDValue(runText)
		if err != nil {
			return nil, nil, err
		}
		item.ScanUnitID, err = parseIDValue(unitText)
		if err != nil {
			return nil, nil, err
		}
		item.StageAttemptID, err = parseIDValue(attemptText)
		if err != nil {
			return nil, nil, err
		}
		item.AssetID, err = parseIDValue(assetText)
		if err != nil {
			return nil, nil, err
		}
		item.EndpointID, err = parseOptionalID(endpointText)
		if err != nil {
			return nil, nil, err
		}
		item.SourceIdentity = deref(sourceIdentity)
		item.ObservationPointID, err = id.Parse(pointText)
		if err != nil {
			return nil, nil, err
		}
		item.EvidenceIDs, err = parseIDs(evidence)
		if err != nil {
			return nil, nil, err
		}
		item.Value = map[string]any{}
		if len(value) > 0 {
			if err := json.Unmarshal(value, &item.Value); err != nil {
				return nil, nil, err
			}
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	rows.Close()
	keyRows, err := tx.Query(ctx, `SELECT idempotency_key, observation_id::text FROM result_idempotency`)
	if err != nil {
		return nil, nil, fmt.Errorf("load idempotency: %w", err)
	}
	defer keyRows.Close()
	keys := map[string]id.ID{}
	for keyRows.Next() {
		var key, idText string
		if err := keyRows.Scan(&key, &idText); err != nil {
			return nil, nil, err
		}
		parsed, err := id.Parse(idText)
		if err != nil {
			return nil, nil, err
		}
		keys[key] = parsed
	}
	return out, keys, keyRows.Err()
}

func loadProducts(ctx context.Context, tx pgx.Tx) (map[id.ID]Product, []identity.Alias, error) {
	rows, err := tx.Query(ctx, `SELECT id::text, ecosystem, product_name, canonical_key FROM product_identity`)
	if err != nil {
		return nil, nil, fmt.Errorf("load products: %w", err)
	}
	defer rows.Close()
	products := map[id.ID]Product{}
	for rows.Next() {
		var item Product
		var idText string
		if err := rows.Scan(&idText, &item.Ecosystem, &item.ProductName, &item.CanonicalKey); err != nil {
			return nil, nil, err
		}
		item.ID, err = id.Parse(idText)
		if err != nil {
			return nil, nil, err
		}
		products[item.ID] = item
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	rows.Close()
	aliasRows, err := tx.Query(ctx, `SELECT id::text, product_identity_id::text, source_name, alias_type, alias_value FROM product_alias`)
	if err != nil {
		return nil, nil, fmt.Errorf("load product aliases: %w", err)
	}
	defer aliasRows.Close()
	var aliases []identity.Alias
	for aliasRows.Next() {
		var item identity.Alias
		var idText, productText string
		if err := aliasRows.Scan(&idText, &productText, &item.Source, &item.AliasType, &item.Value); err != nil {
			return nil, nil, err
		}
		item.ID, err = id.Parse(idText)
		if err != nil {
			return nil, nil, err
		}
		item.ProductID, err = id.Parse(productText)
		if err != nil {
			return nil, nil, err
		}
		if product, ok := products[item.ProductID]; ok {
			item.Ecosystem = product.Ecosystem
		}
		aliases = append(aliases, item)
	}
	return products, aliases, aliasRows.Err()
}

func loadStatements(ctx context.Context, tx pgx.Tx) ([]assess.Statement, error) {
	rows, err := tx.Query(ctx, `
SELECT id::text, source, source_record_id, vulnerability_id, ecosystem, product_selector, affected_ranges, fixed_versions,
       platform_constraints, configuration_constraints, severity_data, severity, kev_status, epss_score::text, published_at,
       modified_at, imported_at, raw_record_digest, normalization_version, supersedes_id::text
FROM intel_statement`)
	if err != nil {
		return nil, fmt.Errorf("load intel statements: %w", err)
	}
	defer rows.Close()
	var out []assess.Statement
	for rows.Next() {
		var item assess.Statement
		var idText string
		var sourceRecord, severity, digest, version, supersedes *string
		var ranges, fixed, platform, configuration, severityData []byte
		var epssText *string
		if err := rows.Scan(&idText, &item.Source, &sourceRecord, &item.VulnerabilityID, &item.Ecosystem, &item.ProductKey, &ranges, &fixed,
			&platform, &configuration, &severityData, &severity, &item.KEV, &epssText, &item.PublishedAt, &item.ModifiedAt, &item.ImportedAt,
			&digest, &version, &supersedes); err != nil {
			return nil, err
		}
		item.ID, err = id.Parse(idText)
		if err != nil {
			return nil, err
		}
		item.SourceRecordID = deref(sourceRecord)
		item.Severity = deref(severity)
		item.RawRecordDigest = deref(digest)
		item.NormalizationVersion = deref(version)
		item.SupersedesID, err = parseIDValue(supersedes)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(ranges, &item.Ranges); err != nil {
			return nil, err
		}
		if len(fixed) > 0 {
			if err := json.Unmarshal(fixed, &item.FixedVersions); err != nil {
				return nil, err
			}
		}
		item.PlatformConstraints = platform
		item.ConfigurationConstraints = configuration
		item.SeverityData = severityData
		if epssText != nil && *epssText != "" {
			score, err := parseEPSS(*epssText)
			if err != nil {
				return nil, err
			}
			item.EPSS = &score
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func loadIntelSnapshots(ctx context.Context, tx pgx.Tx) ([]IntelSnapshot, error) {
	rows, err := tx.Query(ctx, `
SELECT id::text, normalization_version, content_digest, sources, import_batch_id::text, published_at
FROM intel_snapshot`)
	if err != nil {
		return nil, fmt.Errorf("load intel snapshots: %w", err)
	}
	defer rows.Close()
	membersBySnapshot := map[id.ID][]id.ID{}
	var out []IntelSnapshot
	for rows.Next() {
		var item IntelSnapshot
		var idText, batchText string
		if err := rows.Scan(&idText, &item.NormalizationVersion, &item.ContentDigest, &item.Sources, &batchText, &item.PublishedAt); err != nil {
			return nil, err
		}
		item.ID, err = id.Parse(idText)
		if err != nil {
			return nil, err
		}
		item.ImportBatchID, err = id.Parse(batchText)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	members, err := tx.Query(ctx, `SELECT snapshot_id::text, statement_id::text FROM intel_snapshot_statement`)
	if err != nil {
		return nil, fmt.Errorf("load intel snapshot statements: %w", err)
	}
	defer members.Close()
	for members.Next() {
		var snapshotText, statementText string
		if err := members.Scan(&snapshotText, &statementText); err != nil {
			return nil, err
		}
		snapshotID, err := id.Parse(snapshotText)
		if err != nil {
			return nil, err
		}
		statementID, err := id.Parse(statementText)
		if err != nil {
			return nil, err
		}
		membersBySnapshot[snapshotID] = append(membersBySnapshot[snapshotID], statementID)
	}
	if err := members.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].StatementIDs = membersBySnapshot[out[i].ID]
		delete(membersBySnapshot, out[i].ID)
	}
	for snapshotID := range membersBySnapshot {
		return nil, fmt.Errorf("intel snapshot statement references missing snapshot %s", snapshotID)
	}
	return out, nil
}

func backfillSnapshot(statements []assess.Statement, now time.Time) (IntelSnapshot, error) {
	current := currentStatements(statements)
	snapshotID, err := id.New()
	if err != nil {
		return IntelSnapshot{}, err
	}
	batchID, err := id.New()
	if err != nil {
		return IntelSnapshot{}, err
	}
	return IntelSnapshot{
		ID: snapshotID, NormalizationVersion: intel.NormalizationVersion, ContentDigest: snapshotDigest(current),
		Sources: snapshotSources(current), ImportBatchID: batchID, StatementIDs: statementIDs(current), PublishedAt: now,
	}, nil
}

func parseEPSS(value string) (float64, error) {
	var score float64
	if _, err := fmt.Sscan(value, &score); err != nil {
		return 0, fmt.Errorf("parse epss score %q: %w", value, err)
	}
	return score, nil
}

func loadActiveTemplates(ctx context.Context, tx pgx.Tx) ([]activeTemplate, error) {
	rows, err := tx.Query(ctx, `
SELECT id::text, pack_id::text, template_key, template_name, severity, cve_id, request_bound, content_digest, body, enabled
FROM active_template`)
	if err != nil {
		return nil, fmt.Errorf("load active templates: %w", err)
	}
	defer rows.Close()
	var out []activeTemplate
	for rows.Next() {
		var item activeTemplate
		var idText, packText, body string
		if err := rows.Scan(&idText, &packText, &item.Key, &item.Name, &item.Severity, &item.CVE, &item.RequestBound, &item.Digest, &body, &item.Enabled); err != nil {
			return nil, err
		}
		item.ID, err = id.Parse(idText)
		if err != nil {
			return nil, err
		}
		item.PackID, err = id.Parse(packText)
		if err != nil {
			return nil, err
		}
		item.Body = []byte(body)
		out = append(out, item)
	}
	if out == nil {
		out = []activeTemplate{}
	}
	return out, rows.Err()
}

func loadHypotheses(ctx context.Context, tx pgx.Tx) ([]identity.Hypothesis, error) {
	rows, err := tx.Query(ctx, `
SELECT id::text, assessment_run_id::text, endpoint_id::text, observation_point_id::text, service_type, product_identity_id::text,
       raw_product_name, raw_version, normalized_version, confidence::text, supporting_observation_ids::text[], contradicting_observation_ids::text[],
       fingerprint_rule_ids::text[], identity_status, fingerprint_pack_version, evaluated_at
FROM service_hypothesis ORDER BY evaluated_at`)
	if err != nil {
		return nil, fmt.Errorf("load hypotheses: %w", err)
	}
	defer rows.Close()
	var out []identity.Hypothesis
	for rows.Next() {
		var item identity.Hypothesis
		var idText, assessmentText, endpointText, pointText string
		var service, product, rawName, rawVersion, normalized *string
		var supporting, contradicting, rules []string
		if err := rows.Scan(&idText, &assessmentText, &endpointText, &pointText, &service, &product, &rawName, &rawVersion, &normalized, &item.Confidence,
			&supporting, &contradicting, &rules, &item.IdentityStatus, &item.FingerprintPackVersion, &item.EvaluatedAt); err != nil {
			return nil, err
		}
		item.ID, err = id.Parse(idText)
		if err != nil {
			return nil, err
		}
		item.AssessmentRunID, err = id.Parse(assessmentText)
		if err != nil {
			return nil, err
		}
		item.EndpointID, err = id.Parse(endpointText)
		if err != nil {
			return nil, err
		}
		item.ObservationPointID, err = id.Parse(pointText)
		if err != nil {
			return nil, err
		}
		item.ServiceType = deref(service)
		item.ProductIdentityID, err = parseOptionalID(product)
		if err != nil {
			return nil, err
		}
		item.RawProductName = deref(rawName)
		item.RawVersion = deref(rawVersion)
		item.NormalizedVersion = deref(normalized)
		item.SupportingObservationIDs, err = parseIDs(supporting)
		if err != nil {
			return nil, err
		}
		if contradicting != nil {
			item.ContradictingObservationIDs, err = parseIDs(contradicting)
			if err != nil {
				return nil, err
			}
		}
		item.FingerprintRuleIDs, err = parseIDs(rules)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func loadDetections(ctx context.Context, tx pgx.Tx) ([]Detection, error) {
	rows, err := tx.Query(ctx, `
SELECT id::text, assessment_run_id::text, endpoint_id::text, executor_type, subject_type, subject_id::text, rule_id::text, rule_version, vulnerability_id, result_status, severity, summary, matched_conditions, unmatched_conditions, evidence_record_ids::text[], evaluated_at FROM detection_result`)
	if err != nil {
		return nil, fmt.Errorf("load detections: %w", err)
	}
	defer rows.Close()
	var out []Detection
	for rows.Next() {
		var item Detection
		var idText, assessmentText string
		var endpointText, subjectText, ruleText, ruleVersion, vulnerability, severity, summary *string
		var evidence []string
		if err := rows.Scan(&idText, &assessmentText, &endpointText, &item.Executor, &item.SubjectType, &subjectText, &ruleText, &ruleVersion, &vulnerability, &item.ResultStatus, &severity, &summary, &item.Matched, &item.Unmatched, &evidence, &item.EvaluatedAt); err != nil {
			return nil, err
		}
		item.ID, err = id.Parse(idText)
		if err != nil {
			return nil, err
		}
		item.AssessmentRunID, err = id.Parse(assessmentText)
		if err != nil {
			return nil, err
		}
		parsedEndpoint, err := parseOptionalID(endpointText)
		if err != nil {
			return nil, err
		}
		if parsedEndpoint != nil {
			item.EndpointID = *parsedEndpoint
		}
		parsedSubject, err := parseOptionalID(subjectText)
		if err != nil {
			return nil, err
		}
		if parsedSubject != nil {
			item.SubjectID = *parsedSubject
		}
		item.RuleID, err = parseIDValue(ruleText)
		if err != nil {
			return nil, err
		}
		item.RuleVersion = deref(ruleVersion)
		item.VulnerabilityID = deref(vulnerability)
		item.Severity = deref(severity)
		item.Summary = deref(summary)
		item.EvidenceIDs, err = parseIDs(evidence)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func loadFindings(ctx context.Context, tx pgx.Tx) (map[string]*Finding, []Occurrence, error) {
	rows, err := tx.Query(ctx, `
SELECT id::text, finding_key, finding_type, asset_id::text, endpoint_id::text, product_identity_id::text, rule_id::text, external_vulnerability_id, title, severity, status, first_seen_at, last_seen_at, resolved_at, last_occurrence_id::text
FROM finding`)
	if err != nil {
		return nil, nil, fmt.Errorf("load findings: %w", err)
	}
	defer rows.Close()
	findings := map[string]*Finding{}
	for rows.Next() {
		var item Finding
		var idText string
		var asset, endpoint, product, ruleText, vulnerability, occurrence *string
		if err := rows.Scan(&idText, &item.FindingKey, &item.FindingType, &asset, &endpoint, &product, &ruleText, &vulnerability, &item.Title, &item.Severity, &item.Status, &item.FirstSeenAt, &item.LastSeenAt, &item.ResolvedAt, &occurrence); err != nil {
			return nil, nil, err
		}
		item.ID, err = id.Parse(idText)
		if err != nil {
			return nil, nil, err
		}
		parsedAsset, err := parseOptionalID(asset)
		if err != nil {
			return nil, nil, err
		}
		if parsedAsset != nil {
			item.AssetID = *parsedAsset
		}
		parsed, err := parseOptionalID(endpoint)
		if err != nil {
			return nil, nil, err
		}
		if parsed != nil {
			item.EndpointID = *parsed
		}
		item.ProductID, err = parseIDValue(product)
		if err != nil {
			return nil, nil, err
		}
		item.RuleID, err = parseIDValue(ruleText)
		if err != nil {
			return nil, nil, err
		}
		item.VulnerabilityID = deref(vulnerability)
		item.LastOccurrenceID, err = parseIDValue(occurrence)
		if err != nil {
			return nil, nil, err
		}
		findings[item.FindingKey] = &item
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	rows.Close()
	occRows, err := tx.Query(ctx, `
SELECT id::text, finding_id::text, assessment_run_id::text, detection_result_id::text, observed_at, severity, evidence_record_ids::text[], condition_digest FROM finding_occurrence`)
	if err != nil {
		return nil, nil, fmt.Errorf("load occurrences: %w", err)
	}
	defer occRows.Close()
	var occurrences []Occurrence
	for occRows.Next() {
		var item Occurrence
		var idText, findingText, assessmentText, detectionText string
		var evidence []string
		if err := occRows.Scan(&idText, &findingText, &assessmentText, &detectionText, &item.ObservedAt, &item.Severity, &evidence, &item.ConditionDigest); err != nil {
			return nil, nil, err
		}
		item.EvidenceIDs, err = parseIDs(evidence)
		if err != nil {
			return nil, nil, err
		}
		item.ID, err = id.Parse(idText)
		if err != nil {
			return nil, nil, err
		}
		item.FindingID, err = id.Parse(findingText)
		if err != nil {
			return nil, nil, err
		}
		item.AssessmentRunID, err = id.Parse(assessmentText)
		if err != nil {
			return nil, nil, err
		}
		item.DetectionID, err = id.Parse(detectionText)
		if err != nil {
			return nil, nil, err
		}
		occurrences = append(occurrences, item)
	}
	return findings, occurrences, occRows.Err()
}

func loadDispositions(ctx context.Context, tx pgx.Tx) ([]Disposition, error) {
	rows, err := tx.Query(ctx, `
SELECT id::text, finding_id::text, disposition_type, reason, scope, created_by::text, approved_by::text, valid_from, valid_until, created_at
FROM disposition ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("load dispositions: %w", err)
	}
	defer rows.Close()
	var out []Disposition
	for rows.Next() {
		var item Disposition
		var idText, findingText string
		var scope []byte
		var createdBy, approvedBy *string
		if err := rows.Scan(&idText, &findingText, &item.Type, &item.Reason, &scope, &createdBy, &approvedBy, &item.ValidFrom, &item.ValidUntil, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.ID, err = id.Parse(idText)
		if err != nil {
			return nil, err
		}
		item.FindingID, err = id.Parse(findingText)
		if err != nil {
			return nil, err
		}
		item.CreatedBy, err = parseIDValue(createdBy)
		if err != nil {
			return nil, err
		}
		item.ApprovedBy, err = parseIDValue(approvedBy)
		if err != nil {
			return nil, err
		}
		if len(scope) > 0 {
			item.Scope = append(json.RawMessage(nil), scope...)
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func parseOptionalID(value *string) (*id.ID, error) {
	if value == nil || *value == "" {
		return nil, nil
	}
	parsed, err := id.Parse(*value)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func parseIDValue(value *string) (id.ID, error) {
	parsed, err := parseOptionalID(value)
	if err != nil || parsed == nil {
		return id.ID{}, err
	}
	return *parsed, nil
}

func parseStoredAddr(value string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(value); err == nil {
		return addr.Unmap(), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse stored address %q: %w", value, err)
	}
	return prefix.Addr().Unmap(), nil
}

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
