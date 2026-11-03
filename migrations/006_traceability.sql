ALTER TABLE stage_attempt ADD COLUMN heartbeat_at timestamptz;
ALTER TABLE stage_attempt ADD CONSTRAINT stage_attempt_status_check
CHECK (status IN ('claimed', 'running', 'succeeded', 'retryable_error', 'fatal_error', 'cancelled', 'lease_lost'));

ALTER TABLE observation ADD COLUMN asset_id uuid;
ALTER TABLE observation ADD COLUMN source_identity text;

ALTER TABLE assessment_run ADD COLUMN target_asset_id uuid;

ALTER TABLE detection_result ADD COLUMN evidence_record_ids uuid[] NOT NULL DEFAULT '{}';

ALTER TABLE finding ADD COLUMN last_occurrence_id uuid;

CREATE INDEX asset_identity_seen_idx ON asset (identity_status, last_observed_at);
CREATE INDEX observation_endpoint_observed_idx ON observation (endpoint_id, observed_at DESC);
CREATE INDEX observation_asset_type_observed_idx ON observation (asset_id, observation_type, observed_at DESC);
CREATE INDEX evidence_content_digest_idx ON evidence_record (content_digest);
CREATE INDEX service_hypothesis_endpoint_evaluated_idx ON service_hypothesis (endpoint_id, evaluated_at DESC);
CREATE INDEX detection_result_assessment_status_idx ON detection_result (assessment_run_id, result_status);
CREATE INDEX finding_status_severity_seen_idx ON finding (status, severity, last_seen_at DESC);
CREATE INDEX finding_occurrence_finding_observed_idx ON finding_occurrence (finding_id, observed_at DESC);
