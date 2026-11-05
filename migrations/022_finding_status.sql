ALTER TABLE finding ADD CONSTRAINT finding_status_known
    CHECK (status IN ('open', 'confirmed', 'accepted', 'suppressed', 'resolved', 'reopened'));
