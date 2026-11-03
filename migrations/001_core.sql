-- PostgreSQL schema for the single-node control service.
-- vesperd applies this file once and records it in schema_migration.
-- One control process is the writer. Task state is read back from these tables after restart.

CREATE TABLE schema_migration (
    filename text PRIMARY KEY,
    applied_at timestamptz NOT NULL
);

CREATE TABLE scan_target (
    id uuid PRIMARY KEY,
    target_type text NOT NULL CHECK (target_type IN ('ip', 'cidr', 'hostname', 'endpoint')),
    raw_value text NOT NULL,
    normalized_value text NOT NULL,
    address inet,
    network cidr,
    hostname_ascii text,
    port integer CHECK (port IS NULL OR port BETWEEN 1 AND 65535),
    transport text,
    created_at timestamptz NOT NULL
);

CREATE TABLE scope_grant (
    id uuid PRIMARY KEY,
    name text NOT NULL,
    subject_type text NOT NULL CHECK (subject_type IN ('user', 'system', 'worker_group')),
    subject_id uuid,
    target_selectors jsonb NOT NULL,
    allowed_transports text[] NOT NULL,
    allowed_ports jsonb NOT NULL,
    allowed_operations text[] NOT NULL,
    observation_point_ids uuid[],
    valid_from timestamptz NOT NULL,
    valid_until timestamptz,
    max_targets bigint NOT NULL,
    max_addresses bigint NOT NULL,
    max_connections bigint NOT NULL,
    max_requests bigint NOT NULL,
    max_concurrency integer NOT NULL,
    max_rate_per_second numeric(12,3) NOT NULL,
    max_runtime_seconds bigint NOT NULL,
    max_evidence_bytes bigint NOT NULL,
    status text NOT NULL CHECK (status IN ('draft', 'active', 'revoked', 'expired')),
    approved_by uuid,
    approved_at timestamptz,
    revoked_at timestamptz,
    revocation_reason text,
    created_at timestamptz NOT NULL
);

CREATE TABLE scope_grant_revision (
    id uuid PRIMARY KEY,
    grant_id uuid NOT NULL REFERENCES scope_grant (id),
    action text NOT NULL,
    actor_id uuid,
    created_at timestamptz NOT NULL
);

CREATE TABLE worker (
    id uuid PRIMARY KEY,
    name text NOT NULL UNIQUE,
    node_role text NOT NULL CHECK (node_role IN ('local', 'remote')),
    platform text NOT NULL,
    architecture text,
    version text NOT NULL,
    capabilities jsonb NOT NULL,
    status text NOT NULL CHECK (status IN ('online', 'degraded', 'offline', 'disabled')),
    last_heartbeat_at timestamptz,
    registered_at timestamptz NOT NULL
);

CREATE TABLE observation_point (
    id uuid PRIMARY KEY,
    name text NOT NULL UNIQUE,
    node_type text NOT NULL CHECK (node_type IN ('local_worker', 'remote_worker', 'local_collector', 'agent')),
    node_id uuid,
    platform text NOT NULL,
    status text NOT NULL CHECK (status IN ('active', 'offline', 'disabled')),
    created_at timestamptz NOT NULL
);

CREATE TABLE scan_run (
    id uuid PRIMARY KEY,
    name text,
    target_ids uuid[] NOT NULL,
    scope_grant_id uuid NOT NULL REFERENCES scope_grant (id),
    scope_grant_digest text NOT NULL,
    observation_point_ids uuid[] NOT NULL,
    probe_profile_version text NOT NULL,
    fingerprint_pack_version text NOT NULL,
    rule_pack_version text NOT NULL,
    product_catalog_version text NOT NULL,
    scope_snapshot jsonb NOT NULL,
    budget_targets bigint NOT NULL,
    budget_addresses bigint NOT NULL,
    budget_connections bigint NOT NULL,
    budget_requests bigint NOT NULL,
    budget_evidence bigint NOT NULL,
    budget_started_at timestamptz,
    budget_next_allowed timestamptz,
    status text NOT NULL CHECK (status IN ('pending', 'planning', 'running', 'cancelling', 'completed', 'completed_with_errors', 'failed', 'cancelled')),
    progress_total bigint NOT NULL,
    progress_done bigint NOT NULL,
    progress_failed bigint NOT NULL,
    progress_skipped bigint NOT NULL,
    failure_summary text,
    created_at timestamptz NOT NULL,
    started_at timestamptz,
    finished_at timestamptz,
    cancel_requested_at timestamptz
);

CREATE INDEX scan_run_status_created_idx ON scan_run (status, created_at);

CREATE TABLE scan_unit (
    id uuid PRIMARY KEY,
    scan_run_id uuid NOT NULL REFERENCES scan_run (id),
    target_id uuid NOT NULL REFERENCES scan_target (id),
    observation_point_id uuid NOT NULL REFERENCES observation_point (id),
    unit_type text NOT NULL,
    stage_key text NOT NULL,
    depends_on_unit_ids uuid[],
    required_capabilities text[] NOT NULL,
    input_snapshot jsonb NOT NULL,
    status text NOT NULL CHECK (status IN ('queued', 'leased', 'running', 'retry_wait', 'succeeded', 'failed', 'cancelled', 'skipped')),
    priority integer NOT NULL,
    attempt_count integer NOT NULL,
    max_attempts integer NOT NULL,
    not_before timestamptz,
    lease_id uuid,
    lease_owner_id uuid,
    lease_expires_at timestamptz,
    fencing_token bigint NOT NULL,
    terminal_reason text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (scan_run_id, stage_key, target_id, observation_point_id)
);

CREATE INDEX scan_unit_claim_idx ON scan_unit (status, priority, not_before);
CREATE INDEX scan_unit_lease_idx ON scan_unit (lease_expires_at);

CREATE TABLE stage_attempt (
    id uuid PRIMARY KEY,
    scan_unit_id uuid NOT NULL REFERENCES scan_unit (id),
    attempt_no integer NOT NULL,
    worker_id uuid NOT NULL,
    lease_id uuid NOT NULL,
    fencing_token bigint NOT NULL,
    status text NOT NULL,
    started_at timestamptz,
    finished_at timestamptz,
    error_code text,
    error_message text,
    created_at timestamptz NOT NULL,
    UNIQUE (scan_unit_id, attempt_no)
);

CREATE TABLE endpoint (
    id uuid PRIMARY KEY,
    asset_id uuid,
    address inet NOT NULL,
    transport text NOT NULL,
    port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    current_state text NOT NULL,
    state_observed_at timestamptz,
    first_observed_at timestamptz NOT NULL,
    last_observed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE INDEX endpoint_address_idx ON endpoint (address, transport, port);

CREATE TABLE asset (
    id uuid PRIMARY KEY,
    asset_type text NOT NULL,
    platform_family text,
    platform_name text,
    platform_version text,
    machine_id_hash text,
    identity_confidence numeric(5,4) NOT NULL,
    identity_status text NOT NULL,
    first_observed_at timestamptz NOT NULL,
    last_observed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE UNIQUE INDEX asset_machine_id_hash_idx ON asset (machine_id_hash) WHERE machine_id_hash IS NOT NULL;

CREATE TABLE assessment_run (
    id uuid PRIMARY KEY,
    assessment_type text NOT NULL,
    source_scan_run_id uuid,
    target_endpoint_id uuid,
    input_observation_ids uuid[] NOT NULL,
    rule_pack_version text,
    fingerprint_pack_version text,
    product_catalog_version text,
    status text NOT NULL,
    started_at timestamptz,
    finished_at timestamptz,
    created_at timestamptz NOT NULL
);

CREATE TABLE intel_statement (
    id uuid PRIMARY KEY,
    source text NOT NULL,
    vulnerability_id text NOT NULL,
    ecosystem text NOT NULL,
    product_selector text NOT NULL,
    affected_ranges jsonb NOT NULL,
    kev_status boolean NOT NULL,
    imported_at timestamptz NOT NULL
);

CREATE TABLE observation (
    id uuid PRIMARY KEY,
    scan_run_id uuid,
    scan_unit_id uuid,
    stage_attempt_id uuid,
    endpoint_id uuid,
    observation_point_id uuid NOT NULL,
    observation_type text NOT NULL,
    subject_key text NOT NULL,
    observed_at timestamptz NOT NULL,
    collected_at timestamptz NOT NULL,
    result_status text NOT NULL,
    value_schema_version text NOT NULL,
    value jsonb,
    evidence_record_ids uuid[],
    source_kind text NOT NULL,
    content_digest text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE evidence_record (
    id uuid PRIMARY KEY,
    storage_backend text NOT NULL,
    storage_key text NOT NULL UNIQUE,
    size_bytes bigint NOT NULL,
    digest_algorithm text NOT NULL,
    content_digest text NOT NULL,
    integrity_status text NOT NULL CHECK (integrity_status IN ('pending', 'verified', 'missing', 'mismatch', 'unavailable')),
    captured_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE product_identity (
    id uuid PRIMARY KEY,
    ecosystem text NOT NULL,
    product_name text NOT NULL,
    canonical_key text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE product_alias (
    id uuid PRIMARY KEY,
    product_identity_id uuid NOT NULL REFERENCES product_identity (id),
    source_name text NOT NULL,
    alias_type text NOT NULL,
    alias_value text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE service_hypothesis (
    id uuid PRIMARY KEY,
    endpoint_id uuid NOT NULL,
    observation_point_id uuid NOT NULL,
    assessment_run_id uuid NOT NULL REFERENCES assessment_run (id),
    service_type text,
    product_identity_id uuid,
    raw_product_name text,
    raw_version text,
    confidence numeric(5,4) NOT NULL,
    supporting_observation_ids uuid[] NOT NULL,
    fingerprint_rule_ids uuid[],
    identity_status text NOT NULL,
    fingerprint_pack_version text NOT NULL,
    evaluated_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE detection_result (
    id uuid PRIMARY KEY,
    assessment_run_id uuid NOT NULL REFERENCES assessment_run (id),
    endpoint_id uuid NOT NULL,
    executor_type text NOT NULL,
    subject_type text NOT NULL,
    subject_id uuid NOT NULL,
    vulnerability_id text,
    result_status text NOT NULL,
    summary text,
    evaluated_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE finding (
    id uuid PRIMARY KEY,
    finding_key text NOT NULL UNIQUE,
    finding_type text NOT NULL,
    endpoint_id uuid,
    external_vulnerability_id text,
    title text NOT NULL,
    severity text NOT NULL,
    status text NOT NULL,
    first_seen_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE finding_occurrence (
    id uuid PRIMARY KEY,
    finding_id uuid NOT NULL REFERENCES finding (id),
    assessment_run_id uuid NOT NULL REFERENCES assessment_run (id),
    detection_result_id uuid NOT NULL,
    observed_at timestamptz NOT NULL,
    severity text NOT NULL,
    condition_digest text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE result_idempotency (
    idempotency_key text PRIMARY KEY,
    observation_id uuid NOT NULL,
    created_at timestamptz NOT NULL
);
