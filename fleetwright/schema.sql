-- FleetWright schema. Applied at every start; every statement is idempotent.

CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    email           TEXT UNIQUE NOT NULL,
    name            TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'viewer',      -- admin | operator | viewer
    password_hash   TEXT,
    setup_token     TEXT,                                -- sha256 of a one-time setup link
    setup_expires   TIMESTAMPTZ,
    last_login      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_log (
    id      BIGSERIAL PRIMARY KEY,
    at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor   TEXT NOT NULL,
    what    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL
);

-- SSH private keys, encrypted with FLEETWRIGHT_SECRET_KEY.
CREATE TABLE IF NOT EXISTS ssh_credentials (
    id              SERIAL PRIMARY KEY,
    name            TEXT UNIQUE NOT NULL,
    username        TEXT NOT NULL,
    private_key_enc TEXT NOT NULL,
    public_key      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS groups (
    id          SERIAL PRIMARY KEY,
    name        TEXT UNIQUE NOT NULL,
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS hosts (
    id                SERIAL PRIMARY KEY,
    name              TEXT UNIQUE NOT NULL,
    address           TEXT NOT NULL DEFAULT '',
    port              INTEGER NOT NULL DEFAULT 22,
    group_id          INTEGER REFERENCES groups (id) ON DELETE SET NULL,
    tags              TEXT[] NOT NULL DEFAULT '{}',
    mode              TEXT NOT NULL,                     -- ssh | agent
    credential_id     INTEGER REFERENCES ssh_credentials (id) ON DELETE SET NULL,
    ssh_host_key      TEXT,                              -- pinned on first connect
    agent_token_hash  TEXT UNIQUE,
    agent_version     TEXT,
    agent_connected   BOOLEAN NOT NULL DEFAULT FALSE,
    os_id             TEXT,                              -- ubuntu | fedora
    os_version        TEXT,
    os_pretty         TEXT,
    pkg_family        TEXT,                              -- apt | dnf
    kernel            TEXT,
    boot_id           TEXT,
    booted_at         TIMESTAMPTZ,
    reboot_required   BOOLEAN NOT NULL DEFAULT FALSE,
    pending_count     INTEGER NOT NULL DEFAULT 0,
    security_count    INTEGER NOT NULL DEFAULT 0,
    held              TEXT[] NOT NULL DEFAULT '{}',      -- never installed by FleetWright
    last_seen         TIMESTAMPTZ,
    last_scan_at      TIMESTAMPTZ,
    last_error        TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS machine_id TEXT;   -- /etc/machine-id, to recognise a re-enrolled host
CREATE INDEX IF NOT EXISTS idx_hosts_group ON hosts (group_id);
CREATE INDEX IF NOT EXISTS idx_hosts_machine ON hosts (machine_id);
CREATE INDEX IF NOT EXISTS idx_hosts_tags ON hosts USING GIN (tags);

CREATE TABLE IF NOT EXISTS pending_updates (
    host_id     INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    arch        TEXT NOT NULL DEFAULT '',
    current     TEXT,                                    -- NULL: a new package pulled in
    available   TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT '',
    is_security BOOLEAN NOT NULL DEFAULT FALSE,
    is_kernel   BOOLEAN NOT NULL DEFAULT FALSE,
    kind        TEXT NOT NULL DEFAULT 'bugfix',          -- security | bugfix | enhancement
    severity    TEXT,                                    -- critical | important | moderate | low
    advisory    TEXT,
    PRIMARY KEY (host_id, name, arch)
);

CREATE TABLE IF NOT EXISTS enroll_tokens (
    id          SERIAL PRIMARY KEY,
    token_hash  TEXT UNIQUE NOT NULL,
    label       TEXT NOT NULL DEFAULT '',
    group_id    INTEGER REFERENCES groups (id) ON DELETE SET NULL,
    tags        TEXT[] NOT NULL DEFAULT '{}',
    uses_left   INTEGER,                                 -- NULL: unlimited until it expires
    expires_at  TIMESTAMPTZ NOT NULL,
    created_by  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Who a policy, booking or run applies to:
-- {"hosts": [ids], "groups": [ids], "tags": [..], "exclude_tags": [..]}
-- What it installs (the "selection"):
-- {"mode": "all"}
-- {"mode": "kinds", "kinds": ["security","kernel","bugfix","enhancement"],
--  "min_severity": "important", "include": ["openssl*"], "exclude": ["nginx"]}
-- {"mode": "packages", "packages": {"<host id>": [{"name": .., "arch": .., "version": ..}]}}

CREATE TABLE IF NOT EXISTS policies (
    id              SERIAL PRIMARY KEY,
    name            TEXT UNIQUE NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    target          JSONB NOT NULL DEFAULT '{}',
    selection       JSONB NOT NULL DEFAULT '{"mode": "kinds", "kinds": ["security"]}',
    repeat          TEXT NOT NULL DEFAULT 'daily',       -- daily | weekly | monthly
    weekdays        INTEGER[] NOT NULL DEFAULT '{}',     -- 0 = Monday, for weekly
    monthday        INTEGER,                             -- 1-28, for monthly
    at_time         TIME NOT NULL DEFAULT '02:00',
    window_minutes  INTEGER NOT NULL DEFAULT 120,
    batch_size      INTEGER NOT NULL DEFAULT 0,          -- 0: all at once
    batch_percent   INTEGER NOT NULL DEFAULT 0,          -- used when batch_size is 0 and this > 0
    canary          BOOLEAN NOT NULL DEFAULT FALSE,
    max_failures    INTEGER NOT NULL DEFAULT 2,
    reboot          TEXT NOT NULL DEFAULT 'if_needed',   -- never | if_needed | always
    next_run_at     TIMESTAMPTZ,
    last_run_id     INTEGER,
    created_by      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS runs (
    id              SERIAL PRIMARY KEY,
    kind            TEXT NOT NULL,                       -- apply | scan | reboot
    title           TEXT NOT NULL,
    created_by      TEXT NOT NULL,
    policy_id       INTEGER REFERENCES policies (id) ON DELETE SET NULL,
    booking_id      INTEGER,
    selection       JSONB NOT NULL DEFAULT '{"mode": "all"}',
    batch_size      INTEGER NOT NULL DEFAULT 0,
    canary          BOOLEAN NOT NULL DEFAULT FALSE,
    max_failures    INTEGER NOT NULL DEFAULT 0,          -- 0: never stop
    reboot          TEXT NOT NULL DEFAULT 'never',
    window_end      TIMESTAMPTZ,
    on_window_close TEXT NOT NULL DEFAULT 'finish_started', -- finish_started | stop | carry_on
    status          TEXT NOT NULL DEFAULT 'running',     -- running | paused | done | failed | aborted | stopped
    current_batch   INTEGER NOT NULL DEFAULT 0,
    note            TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_runs_status ON runs (status);

-- One unit of work on one host. Scans scheduled by the worker have no run.
CREATE TABLE IF NOT EXISTS tasks (
    id          BIGSERIAL PRIMARY KEY,
    run_id      INTEGER REFERENCES runs (id) ON DELETE CASCADE,
    host_id     INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    op          TEXT NOT NULL,                           -- scan | apply | reboot
    args        JSONB NOT NULL DEFAULT '{}',
    batch       INTEGER NOT NULL DEFAULT 0,
    status      TEXT NOT NULL DEFAULT 'queued',          -- waiting | queued | running | done | failed | skipped
    claimed_by  TEXT,
    detail      TEXT,
    log         TEXT NOT NULL DEFAULT '',
    result      JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at  TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_tasks_queue ON tasks (status, id) WHERE status = 'queued';
CREATE INDEX IF NOT EXISTS idx_tasks_run ON tasks (run_id, batch);
CREATE INDEX IF NOT EXISTS idx_tasks_host ON tasks (host_id, id DESC);

CREATE TABLE IF NOT EXISTS package_changes (
    id           BIGSERIAL PRIMARY KEY,
    task_id      BIGINT REFERENCES tasks (id) ON DELETE SET NULL,
    host_id      INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    from_version TEXT,
    to_version   TEXT,
    at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_changes_host ON package_changes (host_id, at DESC);
CREATE INDEX IF NOT EXISTS idx_changes_at ON package_changes (at);

-- One-off installs booked for a window.
CREATE TABLE IF NOT EXISTS bookings (
    id              SERIAL PRIMARY KEY,
    title           TEXT NOT NULL,
    target          JSONB NOT NULL,
    selection       JSONB NOT NULL,
    window_start    TIMESTAMPTZ NOT NULL,
    window_end      TIMESTAMPTZ NOT NULL,
    on_window_close TEXT NOT NULL DEFAULT 'finish_started',
    batch_size      INTEGER NOT NULL DEFAULT 1,
    reboot          TEXT NOT NULL DEFAULT 'if_needed',
    rescan          BOOLEAN NOT NULL DEFAULT TRUE,
    needs_approval  BOOLEAN NOT NULL DEFAULT FALSE,
    approved_by     TEXT,
    status          TEXT NOT NULL DEFAULT 'booked',      -- booked | needs_approval | started | done | cancelled | missed
    run_id          INTEGER REFERENCES runs (id) ON DELETE SET NULL,
    created_by      TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_bookings_window ON bookings (status, window_start);
