ALTER TABLE intel_statement ADD COLUMN source_record_id text;
ALTER TABLE intel_statement ADD COLUMN fixed_versions jsonb;
ALTER TABLE intel_statement ADD COLUMN platform_constraints jsonb;
ALTER TABLE intel_statement ADD COLUMN configuration_constraints jsonb;
ALTER TABLE intel_statement ADD COLUMN severity_data jsonb;
ALTER TABLE intel_statement ADD COLUMN severity text;
ALTER TABLE intel_statement ADD COLUMN epss_score numeric(8,7);
ALTER TABLE intel_statement ADD COLUMN published_at timestamptz;
ALTER TABLE intel_statement ADD COLUMN modified_at timestamptz;
ALTER TABLE intel_statement ADD COLUMN raw_record_digest text;
ALTER TABLE intel_statement ADD COLUMN normalization_version text;
ALTER TABLE intel_statement ADD COLUMN supersedes_id uuid;

ALTER TABLE intel_statement ADD CONSTRAINT intel_statement_severity_chk
    CHECK (severity IS NULL OR severity IN ('info', 'low', 'medium', 'high', 'critical'));
ALTER TABLE intel_statement ADD CONSTRAINT intel_statement_epss_chk
    CHECK (epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1));

CREATE UNIQUE INDEX intel_statement_source_record_digest_idx
    ON intel_statement (source, source_record_id, raw_record_digest)
    WHERE source_record_id IS NOT NULL AND raw_record_digest IS NOT NULL;

CREATE TABLE intel_snapshot (
    id uuid PRIMARY KEY,
    normalization_version text NOT NULL,
    content_digest text NOT NULL,
    sources text[] NOT NULL,
    import_batch_id uuid NOT NULL,
    published_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE intel_snapshot_statement (
    snapshot_id uuid NOT NULL REFERENCES intel_snapshot (id),
    statement_id uuid NOT NULL REFERENCES intel_statement (id),
    PRIMARY KEY (snapshot_id, statement_id)
);

ALTER TABLE scan_run ADD COLUMN intel_snapshot_id uuid REFERENCES intel_snapshot (id);
ALTER TABLE assessment_run ADD COLUMN intel_snapshot_id uuid REFERENCES intel_snapshot (id);
