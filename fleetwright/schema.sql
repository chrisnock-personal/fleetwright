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
-- The agent's own uuid in /etc/fleetwright-agent/instance-id: containers from one image
-- share a machine id and a boot id, but get one of these each. NULL: an older agent,
-- or a host enrolled before this was recorded; enrolment uses the old checks then.
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS instance_id TEXT;
-- Other tools that install updates (unattended-upgrades, dnf-automatic), from the last scan:
-- [{"tool": .., "installs": bool, "detail": ..}]. NULL: not reported (an older agent).
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS auto_updates JSONB;
-- OS-level package holds reported by the last scan (apt-mark showhold / dnf versionlock list).
-- Unlike hosts.held, these are set outside FleetWright; an empty array means none were reported.
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS os_holds TEXT[] NOT NULL DEFAULT '{}';
-- The agent's files as one id (agents from 0.3.0 report it); compared with the server's
-- to tell an outdated agent. NULL: an older agent, which can't update itself.
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS agent_bundle TEXT;
-- The HTTPS public-key pin this agent last enrolled, connected or acknowledged with.
-- NULL: not recorded (an older agent, or FleetWright isn't serving HTTPS itself).
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS agent_tls_pin TEXT;
-- The hostname the machine reports (the host's name in FleetWright can be changed);
-- one of the ways a reinstall is told from a cloned machine.
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS hostname TEXT;
CREATE INDEX IF NOT EXISTS idx_hosts_group ON hosts (group_id);
CREATE INDEX IF NOT EXISTS idx_hosts_machine ON hosts (machine_id);
CREATE INDEX IF NOT EXISTS idx_hosts_instance ON hosts (instance_id);
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
-- The overview's security advisories and critical hosts, without scanning every pending update.
CREATE INDEX IF NOT EXISTS idx_pending_security ON pending_updates (advisory) WHERE is_security;
CREATE INDEX IF NOT EXISTS idx_pending_critical ON pending_updates (host_id) WHERE severity = 'critical';

-- Trigram indexes for the hosts page's package search (ILIKE '%…%'), which otherwise
-- scans every pending update. Optional: skipped where the extension can't be created
-- (a managed database without it); search still works, just slower on big fleets.
DO $$ BEGIN
    CREATE EXTENSION IF NOT EXISTS pg_trgm;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'pg_trgm unavailable (%), package search will scan', SQLERRM;
END $$;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm') THEN
        CREATE INDEX IF NOT EXISTS idx_pending_name_trgm ON pending_updates USING GIN (name gin_trgm_ops);
        CREATE INDEX IF NOT EXISTS idx_pending_advisory_trgm ON pending_updates USING GIN (advisory gin_trgm_ops);
    END IF;
END $$;

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
-- A run's page counts each task's changes; deleting old tasks nulls their task_id.
CREATE INDEX IF NOT EXISTS idx_changes_task ON package_changes (task_id);

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

-- Notifications (notify.py). One channel: where to send and which events it wants.
-- config: email {host, port, security: starttls|ssl|none, username, from, to}; webhook and
-- ntfy {url}. secret_enc: the SMTP password, the webhook signing secret or the ntfy token.
CREATE TABLE IF NOT EXISTS notify_channels (
    id            SERIAL PRIMARY KEY,
    name          TEXT UNIQUE NOT NULL,
    kind          TEXT NOT NULL,                       -- email | webhook | ntfy
    config        JSONB NOT NULL DEFAULT '{}',
    secret_enc    TEXT,
    events        TEXT[] NOT NULL DEFAULT '{run_failed,unreachable,approval,critical}',
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    last_sent_at  TIMESTAMPTZ,
    last_error    TEXT,
    created_by    TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS notify_outbox (
    id          BIGSERIAL PRIMARY KEY,
    channel_id  INTEGER NOT NULL REFERENCES notify_channels (id) ON DELETE CASCADE,
    event       TEXT NOT NULL,
    subject     TEXT NOT NULL,
    body        TEXT NOT NULL DEFAULT '',
    link        TEXT,
    urgent      BOOLEAN NOT NULL DEFAULT FALSE,
    attempts    INTEGER NOT NULL DEFAULT 0,
    next_try    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at     TIMESTAMPTZ,                           -- 'epoch': given up
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_outbox_due ON notify_outbox (next_try) WHERE sent_at IS NULL;

-- Set once a host has been reported unreachable, cleared (and reported) when it's back.
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS unreachable_notified BOOLEAN NOT NULL DEFAULT FALSE;

-- API tokens (api.py): each belongs to a person and acts with at most their role.
-- The token itself is shown once; only its SHA-256 is kept, plus its first characters to
-- tell tokens apart.
CREATE TABLE IF NOT EXISTS api_tokens (
    id            SERIAL PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    token_hash    TEXT UNIQUE NOT NULL,
    prefix        TEXT NOT NULL,
    role          TEXT NOT NULL,                       -- never above the person's role
    expires_at    TIMESTAMPTZ,
    last_used_at  TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, name)
);

-- Idempotency-Key on API requests that start runs: a retried request returns the first
-- one's answer instead of starting another run. Kept a day.
CREATE TABLE IF NOT EXISTS api_idempotency (
    token_id    INTEGER NOT NULL REFERENCES api_tokens (id) ON DELETE CASCADE,
    key         TEXT NOT NULL,
    endpoint    TEXT NOT NULL,
    response    JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (token_id, key)
);
-- The row is inserted before start() runs, so a concurrent request with the same key
-- can't start a second run (INSERT ... ON CONFLICT claims the key atomically). While
-- start() is running response is NULL and claim identifies its request; a failed start
-- deletes only its own claim, and a finished response is never overwritten.
ALTER TABLE api_idempotency ALTER COLUMN response DROP NOT NULL;
ALTER TABLE api_idempotency ADD COLUMN IF NOT EXISTS claim TEXT;
