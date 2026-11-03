ALTER TABLE scan_run ADD COLUMN trigger_type text;
ALTER TABLE scan_run ADD COLUMN effective_budget jsonb;

UPDATE scan_run SET trigger_type = 'manual' WHERE trigger_type IS NULL;
UPDATE scan_run SET effective_budget = '{}'::jsonb WHERE effective_budget IS NULL;

ALTER TABLE scan_run ALTER COLUMN trigger_type SET NOT NULL;
ALTER TABLE scan_run ALTER COLUMN effective_budget SET NOT NULL;
ALTER TABLE scan_run ADD CONSTRAINT scan_run_trigger_type_check CHECK (trigger_type IN ('manual', 'scheduled', 'reassessment', 'verification'));

UPDATE observation
SET value = COALESCE(value, '{}'::jsonb) || jsonb_build_object('collection_status', result_status)
WHERE observation_type = 'host_inventory'
  AND result_status IN ('collected', 'empty', 'permission_denied', 'unsupported', 'error', 'not_requested')
  AND (value IS NULL OR NOT (value ? 'collection_status'));

UPDATE observation SET result_status = 'observed' WHERE result_status IN ('collected', 'empty');
UPDATE observation SET result_status = 'error' WHERE result_status = 'permission_denied';
UPDATE observation SET result_status = 'not_scanned' WHERE result_status = 'not_requested';
UPDATE observation SET source_kind = 'network' WHERE source_kind = 'dns';

ALTER TABLE observation ADD CONSTRAINT observation_result_status_check
CHECK (result_status IN ('observed', 'no_response', 'unreachable', 'not_scanned', 'unsupported', 'error', 'partial'));

ALTER TABLE observation ADD CONSTRAINT observation_source_kind_check
CHECK (source_kind IN ('network', 'local_collector', 'agent', 'import'));
