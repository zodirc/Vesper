-- Rule packs and host-scoped detection subjects.
-- Published pack content is immutable. A revision requires a new version.

ALTER TABLE detection_result ALTER COLUMN endpoint_id DROP NOT NULL;
ALTER TABLE finding ADD COLUMN asset_id uuid;

CREATE TABLE rule_pack (
    id uuid PRIMARY KEY,
    pack_type text NOT NULL CHECK (pack_type IN ('probe', 'fingerprint', 'config', 'active_detection', 'baseline')),
    version text NOT NULL,
    content_digest text NOT NULL,
    schema_version text NOT NULL,
    source text NOT NULL,
    license_metadata jsonb NOT NULL,
    compatibility jsonb NOT NULL,
    status text NOT NULL CHECK (status IN ('draft', 'validated', 'published', 'deprecated', 'revoked')),
    published_at timestamptz,
    created_at timestamptz NOT NULL,
    UNIQUE (pack_type, version)
);

CREATE TABLE fingerprint_rule (
    id uuid PRIMARY KEY,
    pack_id uuid NOT NULL REFERENCES rule_pack (id),
    rule_key text NOT NULL,
    version text NOT NULL,
    priority integer NOT NULL,
    target_protocol text NOT NULL,
    service_type text NOT NULL,
    match_conditions jsonb NOT NULL,
    extractors jsonb NOT NULL,
    confidence_matched numeric(5,4) NOT NULL,
    confidence_empty numeric(5,4) NOT NULL,
    UNIQUE (pack_id, rule_key)
);

CREATE TABLE config_rule (
    id uuid PRIMARY KEY,
    pack_id uuid NOT NULL REFERENCES rule_pack (id),
    rule_key text NOT NULL,
    version text NOT NULL,
    subject_type text NOT NULL,
    required_observation_type text NOT NULL,
    operation text NOT NULL,
    pass_field text NOT NULL,
    severity text NOT NULL,
    UNIQUE (pack_id, rule_key)
);
