ALTER TABLE scope_grant_revision ADD COLUMN content jsonb;

ALTER TABLE detection_result ADD COLUMN rule_id uuid;
ALTER TABLE detection_result ADD COLUMN rule_version text;
ALTER TABLE detection_result ADD COLUMN severity text;

ALTER TABLE finding ADD COLUMN product_identity_id uuid;
ALTER TABLE finding ADD COLUMN rule_id uuid;
