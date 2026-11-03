ALTER TABLE evidence_record ADD COLUMN content_type text;
ALTER TABLE evidence_record ADD COLUMN content_encoding text;

UPDATE evidence_record SET content_encoding = 'identity' WHERE content_encoding IS NULL;
UPDATE evidence_record SET content_type = 'application/http' WHERE content_type IS NULL AND source_module = 'httpprobe';
UPDATE evidence_record SET content_type = 'application/pkix-cert' WHERE content_type IS NULL AND source_module = 'tlsprobe' AND evidence_type = 'tls_certificate';
UPDATE evidence_record SET content_type = 'text/plain' WHERE content_type IS NULL AND source_module = 'sshprobe';

ALTER TABLE observation_point ADD COLUMN architecture text;
ALTER TABLE observation_point ADD COLUMN last_seen_at timestamptz;
