UPDATE evidence_record SET storage_backend = 'local_fs' WHERE storage_backend = 'filesystem';

ALTER TABLE evidence_record ADD COLUMN evidence_type text;
ALTER TABLE evidence_record ADD COLUMN source_module text;
ALTER TABLE evidence_record ADD COLUMN source_attempt_id uuid;
ALTER TABLE evidence_record ADD COLUMN stored_at timestamptz;
ALTER TABLE evidence_record ADD COLUMN sensitivity text;

UPDATE evidence_record SET evidence_type = 'raw_response' WHERE evidence_type IS NULL;
UPDATE evidence_record SET source_module = 'probe' WHERE source_module IS NULL;
UPDATE evidence_record SET sensitivity = 'internal' WHERE sensitivity IS NULL;
UPDATE evidence_record SET stored_at = captured_at WHERE stored_at IS NULL AND integrity_status = 'verified';

ALTER TABLE evidence_record ALTER COLUMN evidence_type SET NOT NULL;
ALTER TABLE evidence_record ALTER COLUMN source_module SET NOT NULL;
ALTER TABLE evidence_record ALTER COLUMN sensitivity SET NOT NULL;

ALTER TABLE evidence_record ADD CONSTRAINT evidence_record_type_check CHECK (evidence_type IN ('raw_response', 'tls_certificate', 'protocol_transcript', 'tool_output', 'host_inventory', 'file_content'));
ALTER TABLE evidence_record ADD CONSTRAINT evidence_record_sensitivity_check CHECK (sensitivity IN ('public', 'internal', 'sensitive'));
ALTER TABLE evidence_record ADD CONSTRAINT evidence_record_backend_check CHECK (storage_backend IN ('local_fs'));

ALTER TABLE finding_occurrence ADD COLUMN evidence_record_ids uuid[] NOT NULL DEFAULT '{}';
