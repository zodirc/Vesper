ALTER TABLE scan_unit ADD COLUMN result_summary jsonb;
ALTER TABLE stage_attempt ADD COLUMN resource_usage jsonb;
ALTER TABLE stage_attempt ADD COLUMN result_digest text;
