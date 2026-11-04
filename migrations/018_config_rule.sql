ALTER TABLE config_rule ADD COLUMN title text;
ALTER TABLE config_rule ADD COLUMN category text;
ALTER TABLE config_rule ADD COLUMN remediation text;
ALTER TABLE config_rule ADD COLUMN applicability jsonb;
ALTER TABLE config_rule ADD COLUMN pass_conditions jsonb;
ALTER TABLE config_rule ADD COLUMN fail_conditions jsonb;
