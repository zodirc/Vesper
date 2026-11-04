ALTER TABLE fingerprint_rule ADD COLUMN negative_conditions jsonb;
ALTER TABLE fingerprint_rule ADD COLUMN evidence_types jsonb;
