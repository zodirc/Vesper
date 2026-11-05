ALTER TABLE scan_run DROP CONSTRAINT scan_run_trigger_type_check;

ALTER TABLE scan_run ADD CONSTRAINT scan_run_trigger_type_check
    CHECK (trigger_type IN ('manual', 'scheduled', 'reassessment', 'verification', 'supplemental'));
