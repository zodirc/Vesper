ALTER TABLE service_hypothesis ADD COLUMN contradicting_observation_ids uuid[];
ALTER TABLE assessment_run ADD COLUMN result_summary jsonb;
ALTER TABLE detection_result ADD COLUMN matched_conditions jsonb;
ALTER TABLE detection_result ADD COLUMN unmatched_conditions jsonb;
