package control

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/identity"
	"github.com/zodirc/Vesper/internal/intel"
	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/internal/task"
)

func saveAll(ctx context.Context, tx pgx.Tx, s *Service) error {
	if err := saveNode(ctx, tx, s); err != nil {
		return err
	}
	if err := saveGrants(ctx, tx, s); err != nil {
		return err
	}
	if err := saveCatalog(ctx, tx, s); err != nil {
		return err
	}
	if err := saveStatements(ctx, tx, s); err != nil {
		return err
	}
	if err := saveSnapshots(ctx, tx, s); err != nil {
		return err
	}
	if err := saveTasks(ctx, tx, s); err != nil {
		return err
	}
	if err := saveEvidence(ctx, tx, s); err != nil {
		return err
	}
	if err := saveObservations(ctx, tx, s); err != nil {
		return err
	}
	if err := saveProducts(ctx, tx, s); err != nil {
		return err
	}
	if err := savePacks(ctx, tx, s); err != nil {
		return err
	}
	if err := saveAssessment(ctx, tx, s); err != nil {
		return err
	}
	return nil
}

func saveNode(ctx context.Context, tx pgx.Tx, s *Service) error {
	caps := make([]string, 0, len(s.worker.Capabilities))
	for name := range s.worker.Capabilities {
		caps = append(caps, name)
	}
	rawCaps, err := jsonArg(caps)
	if err != nil {
		return err
	}
	now := s.now().UTC()
	_, err = tx.Exec(ctx, `
INSERT INTO observation_point (id, name, node_type, node_id, platform, architecture, status, last_seen_at, created_at)
VALUES ($1::uuid, 'local', 'local_worker', $2::uuid, $3, $4, 'active', $5, $5)
ON CONFLICT (name) DO UPDATE SET
    node_id = EXCLUDED.node_id, platform = EXCLUDED.platform, architecture = EXCLUDED.architecture,
    status = EXCLUDED.status, last_seen_at = EXCLUDED.last_seen_at`,
		s.pointID.String(), s.worker.ID.String(), runtime.GOOS, runtime.GOARCH, now)
	if err != nil {
		return fmt.Errorf("save observation point: %w", err)
	}
	_, err = tx.Exec(ctx, `
INSERT INTO worker (id, name, node_role, platform, architecture, version, capabilities, status, last_heartbeat_at, registered_at)
VALUES ($1::uuid, 'local', 'local', $2, $3, 'builtin-1', $4::jsonb, 'online', $5, $5)
ON CONFLICT (name) DO UPDATE SET
    capabilities = EXCLUDED.capabilities,
    status = EXCLUDED.status,
    platform = EXCLUDED.platform,
    architecture = EXCLUDED.architecture,
    last_heartbeat_at = EXCLUDED.last_heartbeat_at`,
		s.worker.ID.String(), runtime.GOOS, runtime.GOARCH, rawCaps, now)
	if err != nil {
		return fmt.Errorf("save worker: %w", err)
	}
	return nil
}

func saveGrants(ctx context.Context, tx pgx.Tx, s *Service) error {
	for _, grant := range s.grants {
		selectors, err := jsonArg(grant.Selectors)
		if err != nil {
			return err
		}
		ports, err := jsonArg(grant.Ports)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
INSERT INTO scope_grant (
    id, name, subject_type, subject_id, target_selectors, allowed_transports, allowed_ports, allowed_operations,
    observation_point_ids, valid_from, valid_until, max_targets, max_addresses, max_connections, max_requests,
    max_concurrency, max_rate_per_second, max_runtime_seconds, max_evidence_bytes, status, approved_by, approved_at,
    revoked_at, revocation_reason, created_at
) VALUES (
    $1::uuid, $2, $3, $4::uuid, $5::jsonb, $6::text[], $7::jsonb, $8::text[], $9::uuid[], $10, $11,
    $12, $13, $14, $15, $16, $17, $18, $19, $20, $21::uuid, $22, $23, $24, $25
)
ON CONFLICT (id) DO UPDATE SET
    status = EXCLUDED.status, approved_by = EXCLUDED.approved_by, approved_at = EXCLUDED.approved_at,
    revoked_at = EXCLUDED.revoked_at, revocation_reason = EXCLUDED.revocation_reason,
    target_selectors = EXCLUDED.target_selectors, allowed_operations = EXCLUDED.allowed_operations`,
			grant.ID.String(), grant.Name, grant.SubjectType, idArg(derefID(grant.SubjectID)), selectors, textArray(grant.AllowedTransports),
			ports, textArray(grant.AllowedOperations), uuidArray(grant.ObservationPointIDs), grant.ValidFrom.UTC(), timeArg(grant.ValidUntil),
			grant.MaxTargets, grant.MaxAddresses, grant.MaxConnections, grant.MaxRequests, grant.MaxConcurrency, grant.MaxRatePerSecond,
			int64(grant.MaxRuntime/time.Second), grant.MaxEvidenceBytes, grant.Status, idArg(derefID(grant.ApprovedBy)), timeArg(grant.ApprovedAt),
			timeArg(grant.RevokedAt), textArg(grant.RevocationReason), grant.CreatedAt.UTC())
		if err != nil {
			return fmt.Errorf("save grant %s: %w", grant.ID, err)
		}
	}
	for _, revision := range s.revisions {
		_, err := tx.Exec(ctx, `
INSERT INTO scope_grant_revision (id, grant_id, action, actor_id, content, created_at)
VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5::jsonb, $6)
ON CONFLICT (id) DO NOTHING`, revision.ID.String(), revision.GrantID.String(), revision.Action, idArg(revision.ActorID), jsonbArg(revision.Content), revision.At.UTC())
		if err != nil {
			return fmt.Errorf("save grant revision %s: %w", revision.ID, err)
		}
	}
	return nil
}

func saveCatalog(ctx context.Context, tx pgx.Tx, s *Service) error {
	for _, target := range s.catalog.Targets {
		var address, network any
		if target.Address != nil {
			address = target.Address.String()
		}
		if target.Prefix != nil {
			network = target.Prefix.String()
		}
		_, err := tx.Exec(ctx, `
INSERT INTO scan_target (id, target_type, raw_value, normalized_value, address, network, hostname_ascii, port, transport, created_at)
VALUES ($1::uuid, $2, $3, $4, $5::inet, $6::cidr, $7, $8, $9, $10)
ON CONFLICT (id) DO NOTHING`,
			target.ID.String(), target.TargetType, target.RawValue, target.NormalizedValue, address, network,
			textArg(target.Hostname), target.Port, textArg(target.Transport), target.CreatedAt.UTC())
		if err != nil {
			return fmt.Errorf("save target %s: %w", target.ID, err)
		}
	}
	for _, item := range s.catalog.Assets {
		_, err := tx.Exec(ctx, `
INSERT INTO asset (
    id, asset_type, platform_family, platform_name, platform_version, machine_id_hash, identity_confidence,
    identity_status, first_observed_at, last_observed_at, created_at, updated_at
) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7::numeric, $8, $9, $10, $11, $12)
ON CONFLICT (id) DO UPDATE SET
    platform_family = EXCLUDED.platform_family, platform_name = EXCLUDED.platform_name,
    platform_version = EXCLUDED.platform_version, last_observed_at = EXCLUDED.last_observed_at, updated_at = EXCLUDED.updated_at`,
			item.ID.String(), item.AssetType, textArg(item.PlatformFamily), textArg(item.PlatformName), textArg(item.PlatformVersion),
			textArg(item.MachineIDHash), item.IdentityConfidence, item.IdentityStatus, item.FirstObservedAt.UTC(), item.LastObservedAt.UTC(),
			item.CreatedAt.UTC(), item.UpdatedAt.UTC())
		if err != nil {
			return fmt.Errorf("save asset %s: %w", item.ID, err)
		}
	}
	for _, item := range s.catalog.Endpoints {
		_, err := tx.Exec(ctx, `
INSERT INTO endpoint (
    id, asset_id, address, transport, port, current_state, state_observed_at, first_observed_at, last_observed_at, created_at, updated_at
) VALUES ($1::uuid, $2::uuid, $3::inet, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (id) DO UPDATE SET
    asset_id = EXCLUDED.asset_id, current_state = EXCLUDED.current_state, state_observed_at = EXCLUDED.state_observed_at,
    last_observed_at = EXCLUDED.last_observed_at, updated_at = EXCLUDED.updated_at`,
			item.ID.String(), idArg(derefID(item.AssetID)), item.Address.String(), item.Transport, item.Port, item.CurrentState,
			item.StateObservedAt.UTC(), item.FirstObservedAt.UTC(), item.LastObservedAt.UTC(), item.CreatedAt.UTC(), item.UpdatedAt.UTC())
		if err != nil {
			return fmt.Errorf("save endpoint %s: %w", item.ID, err)
		}
	}
	return nil
}

func saveTasks(ctx context.Context, tx pgx.Tx, s *Service) error {
	runs, units, attempts := s.tasks.Export()
	for _, run := range runs {
		grant, ok := s.frozen[run.ID]
		if !ok {
			grant, ok = s.grants[run.ScopeGrantID]
		}
		if !ok {
			return fmt.Errorf("save scan run %s: grant snapshot missing", run.ID)
		}
		snapshot, err := json.Marshal(grant)
		if err != nil {
			return err
		}
		usage := scope.Usage{}
		if account := s.accounts[run.ID]; account != nil {
			usage = account.ExportUsage()
		}
		_, err = tx.Exec(ctx, `
INSERT INTO scan_run (
    id, name, target_ids, scope_grant_id, scope_grant_digest, observation_point_ids, probe_profile_version,
    fingerprint_pack_version, rule_pack_version, product_catalog_version, scope_snapshot, budget_targets,
    budget_addresses, budget_connections, budget_requests, budget_evidence, budget_started_at, budget_next_allowed,
    status, progress_total, progress_done, progress_failed, progress_skipped, failure_summary, created_at, started_at,
    finished_at, cancel_requested_at, plan_snapshot, trigger_type, effective_budget, intel_snapshot_id
) VALUES (
    $1::uuid, $2, $3::uuid[], $4::uuid, $5, $6::uuid[], $7, $8, $9, $10, $11::jsonb, $12, $13, $14, $15, $16, $17, $18,
    $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29::jsonb, $30, $31::jsonb, $32::uuid
)
ON CONFLICT (id) DO UPDATE SET
    status = EXCLUDED.status, progress_total = EXCLUDED.progress_total, progress_done = EXCLUDED.progress_done,
    progress_failed = EXCLUDED.progress_failed, progress_skipped = EXCLUDED.progress_skipped,
    failure_summary = EXCLUDED.failure_summary, started_at = EXCLUDED.started_at, finished_at = EXCLUDED.finished_at,
    cancel_requested_at = EXCLUDED.cancel_requested_at, scope_snapshot = EXCLUDED.scope_snapshot,
    budget_targets = EXCLUDED.budget_targets, budget_addresses = EXCLUDED.budget_addresses,
    budget_connections = EXCLUDED.budget_connections, budget_requests = EXCLUDED.budget_requests,
    budget_evidence = EXCLUDED.budget_evidence, budget_started_at = EXCLUDED.budget_started_at,
    budget_next_allowed = EXCLUDED.budget_next_allowed, plan_snapshot = EXCLUDED.plan_snapshot`,
			run.ID.String(), textArg(run.Name), uuidArray(run.TargetIDs), run.ScopeGrantID.String(), run.ScopeDigest, uuidArray(run.ObservationPointIDs),
			blank(run.ProbeProfileVersion, "builtin-1"), blank(run.FingerprintPackVersion, identity.PackVersion), blank(run.RulePackVersion, "builtin-1"),
			blank(run.ProductCatalogVersion, "builtin-1"), string(snapshot), usage.Targets, usage.Addresses, usage.Connections, usage.Requests, usage.Evidence,
			timeArg(nonZeroTime(usage.Started)), timeArg(nonZeroTime(usage.NextAllowed)), run.Status, run.ProgressTotal, run.ProgressDone, run.ProgressFailed,
			run.ProgressSkipped, textArg(run.FailureSummary), run.CreatedAt.UTC(), timeArg(run.StartedAt), timeArg(run.FinishedAt), timeArg(run.CancelRequestedAt), jsonbArg(run.Plan),
			blank(run.TriggerType, "manual"), jsonbArg(effectiveBudget(run)), idArg(run.IntelSnapshotID))
		if err != nil {
			return fmt.Errorf("save scan run %s: %w", run.ID, err)
		}
	}
	for _, unit := range units {
		input := string(unit.Input)
		if input == "" {
			input = "{}"
		}
		_, err := tx.Exec(ctx, `
INSERT INTO scan_unit (
    id, scan_run_id, target_id, observation_point_id, unit_type, stage_key, depends_on_unit_ids, required_capabilities,
    input_snapshot, status, priority, attempt_count, max_attempts, not_before, lease_id, lease_owner_id, lease_expires_at,
    fencing_token, terminal_reason, result_summary, created_at, updated_at
) VALUES (
    $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6, $7::uuid[], $8::text[], $9::jsonb, $10, $11, $12, $13, $14,
    $15::uuid, $16::uuid, $17, $18, $19, $20::jsonb, $21, $22
)
ON CONFLICT (id) DO UPDATE SET
    status = EXCLUDED.status, attempt_count = EXCLUDED.attempt_count, not_before = EXCLUDED.not_before,
    lease_id = EXCLUDED.lease_id, lease_owner_id = EXCLUDED.lease_owner_id, lease_expires_at = EXCLUDED.lease_expires_at,
    fencing_token = EXCLUDED.fencing_token, terminal_reason = EXCLUDED.terminal_reason, result_summary = EXCLUDED.result_summary,
    updated_at = EXCLUDED.updated_at, depends_on_unit_ids = EXCLUDED.depends_on_unit_ids, input_snapshot = EXCLUDED.input_snapshot`,
			unit.ID.String(), unit.ScanRunID.String(), unit.TargetID.String(), unit.ObservationPointID.String(), unit.UnitType, unit.StageKey,
			uuidArray(unit.DependsOn), textArray(unit.RequiredCapabilities), input, unit.Status, unit.Priority, unit.AttemptCount, unit.MaxAttempts,
			timeArg(unit.NotBefore), idArg(unit.LeaseID), idArg(unit.LeaseOwnerID), timeArg(unit.LeaseExpiresAt), unit.FencingToken,
			textArg(unit.TerminalReason), jsonbArg(unit.ResultSummary), unit.CreatedAt.UTC(), unit.UpdatedAt.UTC())
		if err != nil {
			return fmt.Errorf("save scan unit %s: %w", unit.ID, err)
		}
	}
	for _, attempt := range attempts {
		_, err := tx.Exec(ctx, `
INSERT INTO stage_attempt (
    id, scan_unit_id, attempt_no, worker_id, lease_id, fencing_token, status, started_at, heartbeat_at, finished_at,
    error_code, error_message, resource_usage, result_digest, created_at
) VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5::uuid, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, $14, $15)
ON CONFLICT (id) DO UPDATE SET
    status = EXCLUDED.status, started_at = EXCLUDED.started_at, heartbeat_at = EXCLUDED.heartbeat_at, finished_at = EXCLUDED.finished_at,
    error_code = EXCLUDED.error_code, error_message = EXCLUDED.error_message, resource_usage = EXCLUDED.resource_usage,
    result_digest = EXCLUDED.result_digest`,
			attempt.ID.String(), attempt.ScanUnitID.String(), attempt.AttemptNo, attempt.WorkerID.String(), attempt.LeaseID.String(), attempt.FencingToken,
			attempt.Status, timeArg(attempt.StartedAt), timeArg(attempt.HeartbeatAt), timeArg(attempt.FinishedAt), textArg(attempt.ErrorCode), textArg(attempt.ErrorMessage),
			jsonbArg(attempt.ResourceUsage), textArg(attempt.ResultDigest), attempt.CreatedAt.UTC())
		if err != nil {
			return fmt.Errorf("save stage attempt %s: %w", attempt.ID, err)
		}
	}
	return nil
}

func saveEvidence(ctx context.Context, tx pgx.Tx, s *Service) error {
	for _, item := range s.evidenceRows {
		evidenceType := item.EvidenceType
		if evidenceType == "" {
			evidenceType = "raw_response"
		}
		sourceModule := item.SourceModule
		if sourceModule == "" {
			sourceModule = "probe"
		}
		sensitivity := item.Sensitivity
		if sensitivity == "" {
			sensitivity = "internal"
		}
		_, err := tx.Exec(ctx, `
INSERT INTO evidence_record (
    id, evidence_type, storage_backend, storage_key, content_type, content_encoding, size_bytes, digest_algorithm, content_digest, source_module,
    source_attempt_id, integrity_status, sensitivity, captured_at, stored_at, created_at
) VALUES (
    $1::uuid, $2, 'local_fs', $3, $4, $5, $6, $7, $8, $9, $10::uuid, $11, $12, $13, $14, $13
)
ON CONFLICT (id) DO UPDATE SET
    integrity_status = EXCLUDED.integrity_status, content_digest = EXCLUDED.content_digest,
    evidence_type = EXCLUDED.evidence_type, source_module = EXCLUDED.source_module, content_type = EXCLUDED.content_type,
    content_encoding = EXCLUDED.content_encoding, sensitivity = EXCLUDED.sensitivity, stored_at = EXCLUDED.stored_at`,
			item.ID.String(), evidenceType, item.StorageKey, textArg(item.ContentType), blank(item.ContentEncoding, "identity"), item.SizeBytes, item.DigestAlgorithm, item.ContentDigest, sourceModule,
			idArg(item.SourceAttemptID), item.IntegrityStatus, sensitivity, item.CapturedAt.UTC(), timeArg(item.StoredAt))
		if err != nil {
			return fmt.Errorf("save evidence %s: %w", item.ID, err)
		}
	}
	return nil
}

func saveObservations(ctx context.Context, tx pgx.Tx, s *Service) error {
	for _, item := range s.observations {
		value, err := jsonArg(item.Value)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
INSERT INTO observation (
    id, scan_run_id, scan_unit_id, stage_attempt_id, asset_id, endpoint_id, observation_point_id, observation_type, subject_key,
    observed_at, collected_at, result_status, value_schema_version, value, evidence_record_ids, source_kind, source_identity, content_digest, created_at
) VALUES (
    $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6::uuid, $7::uuid, $8, $9, $10, $11, $12, $13, $14::jsonb, $15::uuid[], $16, $17, $18, $11
)
ON CONFLICT (id) DO NOTHING`,
			item.ID.String(), idArg(item.ScanRunID), idArg(item.ScanUnitID), idArg(item.StageAttemptID), idArg(item.AssetID), idArg(derefID(item.EndpointID)),
			item.ObservationPointID.String(), item.Type, item.SubjectKey, item.ObservedAt.UTC(), item.CollectedAt.UTC(), item.ResultStatus,
			item.ValueSchemaVersion, value, uuidArray(item.EvidenceIDs), item.SourceKind, textArg(item.SourceIdentity), item.ContentDigest)
		if err != nil {
			return fmt.Errorf("save observation %s: %w", item.ID, err)
		}
	}
	for key, observationID := range s.idempotency {
		_, err := tx.Exec(ctx, `
INSERT INTO result_idempotency (idempotency_key, observation_id, created_at) VALUES ($1, $2::uuid, $3)
ON CONFLICT (idempotency_key) DO NOTHING`, key, observationID.String(), s.now().UTC())
		if err != nil {
			return fmt.Errorf("save idempotency %s: %w", key, err)
		}
	}
	return nil
}

func saveProducts(ctx context.Context, tx pgx.Tx, s *Service) error {
	now := s.now().UTC()
	for _, product := range s.products {
		_, err := tx.Exec(ctx, `
INSERT INTO product_identity (id, ecosystem, product_name, canonical_key, created_at, updated_at)
VALUES ($1::uuid, $2, $3, $4, $5, $5)
ON CONFLICT (id) DO NOTHING`, product.ID.String(), product.Ecosystem, product.ProductName, product.CanonicalKey, now)
		if err != nil {
			return fmt.Errorf("save product %s: %w", product.ID, err)
		}
	}
	for i := range s.aliases {
		if s.aliases[i].ID.IsZero() {
			s.aliases[i].ID = id.MustNew()
		}
		alias := s.aliases[i]
		_, err := tx.Exec(ctx, `
INSERT INTO product_alias (id, product_identity_id, source_name, alias_type, alias_value, created_at)
VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)
ON CONFLICT (id) DO NOTHING`, alias.ID.String(), alias.ProductID.String(), alias.Source, alias.AliasType, alias.Value, now)
		if err != nil {
			return fmt.Errorf("save product alias %s: %w", alias.ID, err)
		}
	}
	return nil
}

func saveStatements(ctx context.Context, tx pgx.Tx, s *Service) error {
	for i := range s.statements {
		if s.statements[i].ID.IsZero() {
			s.statements[i].ID = id.MustNew()
		}
		item := s.statements[i]
		ranges, err := jsonArg(item.Ranges)
		if err != nil {
			return err
		}
		fixed, err := jsonList(item.FixedVersions)
		if err != nil {
			return err
		}
		imported := item.ImportedAt
		if imported.IsZero() {
			imported = s.now().UTC()
		}
		_, err = tx.Exec(ctx, `
INSERT INTO intel_statement (
    id, source, source_record_id, vulnerability_id, ecosystem, product_selector, affected_ranges, fixed_versions,
    platform_constraints, configuration_constraints, severity_data, severity, kev_status, epss_score, published_at,
    modified_at, imported_at, raw_record_digest, normalization_version, supersedes_id
) VALUES (
    $1::uuid, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9::jsonb, $10::jsonb, $11::jsonb, $12, $13, $14, $15, $16, $17, $18, $19, $20::uuid
)
ON CONFLICT (id) DO NOTHING`,
			item.ID.String(), blank(item.Source, "local"), textArg(item.SourceRecordID), item.VulnerabilityID, item.Ecosystem, item.ProductKey,
			ranges, fixed, jsonbArg(item.PlatformConstraints), jsonbArg(item.ConfigurationConstraints), jsonbArg(item.SeverityData), textArg(item.Severity),
			item.KEV, item.EPSS, timeArg(item.PublishedAt), timeArg(item.ModifiedAt), imported, textArg(item.RawRecordDigest),
			blank(item.NormalizationVersion, intel.NormalizationVersion), idArg(item.SupersedesID))
		if err != nil {
			return fmt.Errorf("save intel statement %s: %w", item.ID, err)
		}
	}
	return nil
}

func saveSnapshots(ctx context.Context, tx pgx.Tx, s *Service) error {
	for _, item := range s.snapshots {
		if err := insertSnapshot(ctx, tx, item); err != nil {
			return err
		}
	}
	return nil
}

func insertSnapshot(ctx context.Context, tx pgx.Tx, item IntelSnapshot) error {
	_, err := tx.Exec(ctx, `
INSERT INTO intel_snapshot (id, normalization_version, content_digest, sources, import_batch_id, published_at, created_at)
VALUES ($1::uuid, $2, $3, $4::text[], $5::uuid, $6, $6)
ON CONFLICT (id) DO NOTHING`,
		item.ID.String(), blank(item.NormalizationVersion, intel.NormalizationVersion), item.ContentDigest, textArray(item.Sources), item.ImportBatchID.String(), item.PublishedAt.UTC())
	if err != nil {
		return fmt.Errorf("save intel snapshot %s: %w", item.ID, err)
	}
	for _, statementID := range item.StatementIDs {
		if _, err := tx.Exec(ctx, `
INSERT INTO intel_snapshot_statement (snapshot_id, statement_id)
VALUES ($1::uuid, $2::uuid)
ON CONFLICT (snapshot_id, statement_id) DO NOTHING`, item.ID.String(), statementID.String()); err != nil {
			return fmt.Errorf("save intel snapshot %s statement %s: %w", item.ID, statementID, err)
		}
	}
	return nil
}

func jsonList(value any) (string, error) {
	if value == nil {
		return "[]", nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	if string(raw) == "null" {
		return "[]", nil
	}
	return string(raw), nil
}

func saveAssessment(ctx context.Context, tx pgx.Tx, s *Service) error {
	type draft struct {
		kind         string
		asset        id.ID
		endpoint     id.ID
		observations []id.ID
		scanRun      id.ID
		fingerprint  string
		intel        id.ID
		evaluatedAt  time.Time
		seen         map[id.ID]struct{}
	}
	grouped := map[id.ID]*draft{}
	for _, item := range s.hypotheses {
		if item.AssessmentRunID.IsZero() {
			return fmt.Errorf("save hypothesis %s: assessment run is missing", item.ID)
		}
		row := grouped[item.AssessmentRunID]
		if row == nil {
			row = &draft{kind: "service_identification", endpoint: item.EndpointID, fingerprint: item.FingerprintPackVersion, evaluatedAt: item.EvaluatedAt.UTC(), seen: map[id.ID]struct{}{}}
			grouped[item.AssessmentRunID] = row
		}
		for _, observationID := range item.SupportingObservationIDs {
			if _, ok := row.seen[observationID]; ok {
				continue
			}
			row.seen[observationID] = struct{}{}
			row.observations = append(row.observations, observationID)
			for _, observation := range s.observations {
				if observation.ID == observationID && !observation.ScanRunID.IsZero() {
					row.scanRun = observation.ScanRunID
				}
			}
		}
	}
	for _, item := range s.detections {
		if item.AssessmentRunID.IsZero() {
			continue
		}
		row := grouped[item.AssessmentRunID]
		if row == nil {
			kind := "vulnerability"
			assetID := id.ID{}
			if item.SubjectType == "asset" {
				kind = "config"
				assetID = item.SubjectID
			}
			row = &draft{kind: kind, asset: assetID, endpoint: item.EndpointID, intel: item.IntelSnapshotID, evaluatedAt: item.EvaluatedAt.UTC(), seen: map[id.ID]struct{}{}}
			grouped[item.AssessmentRunID] = row
		}
		if row.intel.IsZero() {
			row.intel = item.IntelSnapshotID
		}
		for _, observationID := range item.InputObservationIDs {
			if observationID.IsZero() {
				continue
			}
			if _, ok := row.seen[observationID]; ok {
				continue
			}
			row.seen[observationID] = struct{}{}
			row.observations = append(row.observations, observationID)
			for _, observation := range s.observations {
				if observation.ID == observationID && !observation.ScanRunID.IsZero() {
					row.scanRun = observation.ScanRunID
				}
			}
		}
	}
	for assessmentID, row := range grouped {
		kind := row.kind
		if kind == "" {
			kind = "service_identification"
		}
		summary, err := assessmentResultSummary(hypothesesFor(s, assessmentID), detectionsFor(s, assessmentID))
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
INSERT INTO assessment_run (
    id, assessment_type, source_scan_run_id, target_asset_id, target_endpoint_id, input_observation_ids, rule_pack_version,
    fingerprint_pack_version, product_catalog_version, intel_snapshot_id, status, result_summary, started_at, finished_at, created_at
) VALUES ($1::uuid, $2, $3::uuid, $4::uuid, $5::uuid, $6::uuid[], 'builtin-1', $7, 'builtin-1', $10::uuid, 'completed', $8::jsonb, $9, $9, $9)
ON CONFLICT (id) DO NOTHING`,
			assessmentID.String(), kind, idArg(row.scanRun), idArg(row.asset), idArg(row.endpoint), uuidArray(row.observations), blank(row.fingerprint, identity.PackVersion), jsonbArg(summary), row.evaluatedAt, idArg(row.intel))
		if err != nil {
			return fmt.Errorf("save assessment %s: %w", assessmentID, err)
		}
	}
	for _, item := range s.hypotheses {
		_, err := tx.Exec(ctx, `
INSERT INTO service_hypothesis (
    id, endpoint_id, observation_point_id, assessment_run_id, service_type, product_identity_id, raw_product_name,
    raw_version, confidence, supporting_observation_ids, contradicting_observation_ids, fingerprint_rule_ids, identity_status, fingerprint_pack_version,
    evaluated_at, created_at
) VALUES (
    $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6::uuid, $7, $8, $9::numeric, $10::uuid[], $11::uuid[], $12::uuid[], $13, $14, $15, $15
)
ON CONFLICT (id) DO NOTHING`,
			item.ID.String(), item.EndpointID.String(), item.ObservationPointID.String(), item.AssessmentRunID.String(), textArg(item.ServiceType),
			idArg(derefID(item.ProductIdentityID)), textArg(item.RawProductName), textArg(item.RawVersion), item.Confidence,
			uuidArray(item.SupportingObservationIDs), uuidArrayArg(item.ContradictingObservationIDs), uuidArray(item.FingerprintRuleIDs), item.IdentityStatus, item.FingerprintPackVersion, item.EvaluatedAt.UTC())
		if err != nil {
			return fmt.Errorf("save hypothesis %s: %w", item.ID, err)
		}
	}
	for _, item := range s.detections {
		if item.AssessmentRunID.IsZero() {
			return fmt.Errorf("save detection %s: assessment run is missing", item.ID)
		}
		subjectType := item.SubjectType
		subjectID := item.SubjectID
		if subjectID.IsZero() {
			subjectType = "endpoint"
			subjectID = item.EndpointID
		}
		if subjectID.IsZero() {
			return fmt.Errorf("save detection %s: subject is missing", item.ID)
		}
		// 设计列出的执行器是 nuclei、native_probe、config_engine、fingerprint_engine。
		// 版本适用性判断不属于其中任何一种，因此保留 applicability，不改名充作已列出的执行器。
		// The designed executors are nuclei, native_probe, config_engine, and fingerprint_engine.
		// Version applicability is none of those, so the stored value stays applicability instead of being renamed into a listed executor.
		executor := "applicability"
		if subjectType == "asset" {
			executor = "config_engine"
		}
		_, err := tx.Exec(ctx, `
INSERT INTO detection_result (
    id, assessment_run_id, endpoint_id, executor_type, subject_type, subject_id, rule_id, rule_version, vulnerability_id,
    result_status, severity, summary, matched_conditions, unmatched_conditions, evidence_record_ids, evaluated_at, created_at
) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6::uuid, $7::uuid, $8, $9, $10, $11, $12, $13::jsonb, $14::jsonb, $15::uuid[], $16, $16)
ON CONFLICT (id) DO NOTHING`,
			item.ID.String(), item.AssessmentRunID.String(), idArg(item.EndpointID), executor, subjectType, subjectID.String(), idArg(item.RuleID), textArg(item.RuleVersion), textArg(item.VulnerabilityID), item.ResultStatus, textArg(item.Severity), textArg(item.Summary), jsonbArg(item.Matched), jsonbArg(item.Unmatched), uuidArray(item.EvidenceIDs), item.EvaluatedAt.UTC())
		if err != nil {
			return fmt.Errorf("save detection %s: %w", item.ID, err)
		}
	}
	for _, item := range s.findings {
		findingType := item.FindingType
		if findingType == "" {
			findingType = "vulnerability"
		}
		_, err := tx.Exec(ctx, `
INSERT INTO finding (
    id, finding_key, finding_type, asset_id, endpoint_id, product_identity_id, rule_id, external_vulnerability_id, title, severity, status,
    first_seen_at, last_seen_at, last_occurrence_id, created_at, updated_at
) VALUES ($1::uuid, $2, $3, $4::uuid, $5::uuid, $6::uuid, $7::uuid, $8, $9, $10, $11, $12, $13, $14::uuid, $12, $13)
ON CONFLICT (id) DO UPDATE SET
    status = EXCLUDED.status, severity = EXCLUDED.severity, product_identity_id = EXCLUDED.product_identity_id, rule_id = EXCLUDED.rule_id,
    last_seen_at = EXCLUDED.last_seen_at, last_occurrence_id = EXCLUDED.last_occurrence_id, updated_at = EXCLUDED.updated_at`,
			item.ID.String(), item.FindingKey, findingType, idArg(item.AssetID), idArg(item.EndpointID), idArg(item.ProductID), idArg(item.RuleID), textArg(item.VulnerabilityID), item.Title, item.Severity, item.Status,
			item.FirstSeenAt.UTC(), item.LastSeenAt.UTC(), idArg(item.LastOccurrenceID))
		if err != nil {
			return fmt.Errorf("save finding %s: %w", item.ID, err)
		}
	}
	for _, item := range s.occurrences {
		if item.AssessmentRunID.IsZero() {
			return fmt.Errorf("save occurrence %s: assessment run is missing", item.ID)
		}
		_, err := tx.Exec(ctx, `
INSERT INTO finding_occurrence (
    id, finding_id, assessment_run_id, detection_result_id, observed_at, severity, evidence_record_ids, condition_digest, created_at
) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6, $7::uuid[], $8, $5)
ON CONFLICT (id) DO NOTHING`,
			item.ID.String(), item.FindingID.String(), item.AssessmentRunID.String(), item.DetectionID.String(), item.ObservedAt.UTC(), item.Severity, uuidArray(item.EvidenceIDs), item.ConditionDigest)
		if err != nil {
			return fmt.Errorf("save occurrence %s: %w", item.ID, err)
		}
	}
	return nil
}

func hypothesesFor(s *Service, assessmentID id.ID) []identity.Hypothesis {
	var out []identity.Hypothesis
	for _, item := range s.hypotheses {
		if item.AssessmentRunID == assessmentID {
			out = append(out, item)
		}
	}
	return out
}

func detectionsFor(s *Service, assessmentID id.ID) []Detection {
	var out []Detection
	for _, item := range s.detections {
		if item.AssessmentRunID == assessmentID {
			out = append(out, item)
		}
	}
	return out
}

func assessmentResultSummary(hypotheses []identity.Hypothesis, detections []Detection) (json.RawMessage, error) {
	if len(hypotheses) == 0 && len(detections) == 0 {
		return nil, nil
	}
	payload := struct {
		Hypotheses       int            `json:"hypotheses,omitempty"`
		HypothesisStatus map[string]int `json:"hypothesis_status,omitempty"`
		Detections       int            `json:"detections,omitempty"`
		DetectionStatus  map[string]int `json:"detection_status,omitempty"`
	}{}
	if len(hypotheses) > 0 {
		payload.Hypotheses = len(hypotheses)
		payload.HypothesisStatus = map[string]int{}
		for _, item := range hypotheses {
			payload.HypothesisStatus[item.IdentityStatus]++
		}
	}
	if len(detections) > 0 {
		payload.Detections = len(detections)
		payload.DetectionStatus = map[string]int{}
		for _, item := range detections {
			payload.DetectionStatus[item.ResultStatus]++
		}
	}
	return json.Marshal(payload)
}

func derefID(value *id.ID) id.ID {
	if value == nil {
		return id.ID{}
	}
	return *value
}

func effectiveBudget(run task.Run) json.RawMessage {
	if len(run.EffectiveBudget) == 0 {
		return json.RawMessage(`{}`)
	}
	return run.EffectiveBudget
}

func jsonbArg(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	return string(raw)
}

func blank(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func nonZeroTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	copied := value.UTC()
	return &copied
}
