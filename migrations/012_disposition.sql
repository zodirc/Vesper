ALTER TABLE finding ADD COLUMN resolved_at timestamptz;

CREATE TABLE disposition (
    id uuid PRIMARY KEY,
    finding_id uuid NOT NULL REFERENCES finding (id),
    disposition_type text NOT NULL,
    reason text NOT NULL,
    scope jsonb,
    created_by uuid,
    approved_by uuid,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz,
    created_at timestamptz NOT NULL,
    CONSTRAINT disposition_type_known CHECK (disposition_type IN ('accept_risk', 'suppress', 'false_positive', 'exception', 'reopen', 'resolve')),
    CONSTRAINT disposition_reason_present CHECK (length(btrim(reason)) > 0),
    CONSTRAINT disposition_window CHECK (valid_until IS NULL OR valid_until > valid_from)
);
