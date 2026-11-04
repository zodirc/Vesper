CREATE TABLE active_template (
    id uuid PRIMARY KEY,
    pack_id uuid NOT NULL REFERENCES rule_pack (id),
    template_key text NOT NULL,
    template_name text NOT NULL,
    severity text NOT NULL,
    cve_id text NOT NULL,
    request_bound integer NOT NULL CHECK (request_bound > 0),
    content_digest text NOT NULL,
    body text NOT NULL,
    enabled boolean NOT NULL,
    UNIQUE (pack_id, template_key)
);
