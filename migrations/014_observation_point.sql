CREATE TABLE capability_snapshot (
    id uuid PRIMARY KEY,
    platform text NOT NULL,
    architecture text NOT NULL,
    capabilities jsonb NOT NULL,
    privileges jsonb NOT NULL,
    network_isolation jsonb NOT NULL,
    probe_compatibility jsonb NOT NULL,
    captured_at timestamptz NOT NULL,
    source_version text NOT NULL
);

ALTER TABLE observation_point ADD COLUMN network_interfaces jsonb;
ALTER TABLE observation_point ADD COLUMN capability_snapshot_id uuid REFERENCES capability_snapshot (id);
ALTER TABLE observation_point ADD COLUMN location_label text;

ALTER TABLE worker ADD COLUMN capability_snapshot_id uuid REFERENCES capability_snapshot (id);
