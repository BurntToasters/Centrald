CREATE TABLE centrald_installation (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    instance_id UUID NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE identities (
    id UUID PRIMARY KEY,
    role TEXT NOT NULL CHECK (role IN ('client', 'admin')),
    name TEXT NOT NULL,
    certificate_serial TEXT UNIQUE,
    certificate_fingerprint TEXT UNIQUE,
    elevation_public_key BYTEA,
    capabilities JSONB NOT NULL DEFAULT '["*"]'::jsonb,
    activated_at TIMESTAMPTZ,
    activation_expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revoked_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK ((activated_at IS NULL) = (activation_expires_at IS NOT NULL))
);

CREATE TABLE identity_certificates (
    certificate_fingerprint TEXT PRIMARY KEY,
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    certificate_serial TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK (state IN ('pending', 'active')),
    activation_expires_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    retire_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK ((state = 'pending') = (activation_expires_at IS NOT NULL))
);

CREATE INDEX identity_certificates_identity_idx
    ON identity_certificates (identity_id, state, expires_at DESC);

CREATE TABLE enrollment_keys (
    id UUID PRIMARY KEY,
    role TEXT NOT NULL CHECK (role IN ('client', 'admin')),
    name TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    consumed_by UUID REFERENCES identities(id) ON DELETE SET NULL,
    revoked_at TIMESTAMPTZ,
    revoked_by UUID REFERENCES identities(id) ON DELETE SET NULL,
    revoked_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (NOT (consumed_at IS NOT NULL AND revoked_at IS NOT NULL))
);

CREATE TABLE clients (
    identity_id UUID PRIMARY KEY REFERENCES identities(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    os TEXT NOT NULL,
    os_version TEXT NOT NULL DEFAULT '',
    architecture TEXT NOT NULL,
    client_version TEXT NOT NULL,
    protocol_major INTEGER NOT NULL,
    protocol_minor INTEGER NOT NULL,
    capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
    boot_id TEXT NOT NULL DEFAULT '',
    last_seen TIMESTAMPTZ,
    inventory JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE jobs (
    id UUID PRIMARY KEY,
    request_id UUID NOT NULL,
    target_id UUID NOT NULL REFERENCES identities(id),
    actor_id UUID NOT NULL REFERENCES identities(id),
    kind TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'queued', 'dispatched', 'acknowledged', 'running',
        'succeeded', 'failed', 'canceled', 'timed_out'
    )),
    parameters JSONB NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    idempotency_key UUID NOT NULL,
    delivery_id UUID,
    delivery_lease_expires_at TIMESTAMPTZ,
    execution_start_expires_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (actor_id, request_id),
    UNIQUE (actor_id, idempotency_key),
    CHECK ((state = 'dispatched') = (delivery_id IS NOT NULL AND delivery_lease_expires_at IS NOT NULL)),
    CHECK ((state = 'acknowledged') = (execution_start_expires_at IS NOT NULL))
);

CREATE TABLE job_events (
    job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    sequence BIGINT NOT NULL CHECK (sequence >= 0),
    state TEXT NOT NULL CHECK (state IN (
        'dispatched', 'acknowledged', 'running',
        'succeeded', 'failed', 'canceled', 'timed_out'
    )),
    output BYTEA NOT NULL DEFAULT ''::bytea,
    stderr BOOLEAN NOT NULL DEFAULT FALSE,
    exit_code INTEGER,
    terminal BOOLEAN NOT NULL DEFAULT FALSE,
    CHECK (octet_length(output) <= 65536),
    CHECK (terminal = (state IN ('succeeded', 'failed', 'canceled', 'timed_out'))),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (job_id, sequence)
);

CREATE TABLE shell_sessions (
    id UUID PRIMARY KEY,
    target_id UUID NOT NULL REFERENCES identities(id),
    actor_id UUID NOT NULL REFERENCES identities(id),
    privilege TEXT NOT NULL CHECK (privilege IN ('low', 'elevated')),
    reason TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMPTZ,
    outcome TEXT,
    input_bytes BIGINT NOT NULL DEFAULT 0,
    output_bytes BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE elevation_challenges (
    id UUID PRIMARY KEY,
    admin_id UUID NOT NULL REFERENCES identities(id),
    target_id UUID NOT NULL REFERENCES identities(id),
    operation TEXT NOT NULL,
    nonce BYTEA NOT NULL,
    context_hash BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE update_snapshots (
    id UUID PRIMARY KEY,
    target_id UUID REFERENCES identities(id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    updates JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE audit_entries (
    sequence BIGSERIAL UNIQUE NOT NULL,
    id UUID PRIMARY KEY,
    actor_id UUID REFERENCES identities(id) ON DELETE SET NULL,
    actor_label TEXT NOT NULL,
    action TEXT NOT NULL,
    target_id UUID REFERENCES identities(id) ON DELETE SET NULL,
    outcome TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    previous_hash BYTEA,
    entry_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX jobs_target_state_idx ON jobs (target_id, state, created_at);
CREATE INDEX jobs_dispatch_lease_idx ON jobs (delivery_lease_expires_at)
    WHERE state = 'dispatched';
CREATE INDEX jobs_execution_start_lease_idx ON jobs (execution_start_expires_at)
    WHERE state = 'acknowledged';
CREATE INDEX audit_created_idx ON audit_entries (created_at DESC);
CREATE INDEX audit_sequence_idx ON audit_entries (sequence DESC);
CREATE INDEX enrollment_expiry_idx ON enrollment_keys (expires_at)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;
CREATE INDEX pending_identity_expiry_idx ON identities (activation_expires_at)
    WHERE activated_at IS NULL AND revoked_at IS NULL;
