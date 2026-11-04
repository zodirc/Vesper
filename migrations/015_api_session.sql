CREATE TABLE api_principal (
    id uuid PRIMARY KEY,
    singleton boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL,
    CONSTRAINT api_principal_singleton UNIQUE (singleton)
);

CREATE TABLE api_session (
    token uuid PRIMARY KEY,
    principal_id uuid NOT NULL REFERENCES api_principal (id),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE INDEX api_session_expires_idx ON api_session (expires_at);
