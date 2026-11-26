# The FleetWright API

Everything the web pages can do, as JSON at `/api/v1`, with the same roles. Each
endpoint calls the same action the page does (`fleetwright/actions/`), and the
action checks the role, so the UI and the API can't drift apart: tests check
that no page checks a role itself and that every action has an endpoint.

The full, browsable reference is served by FleetWright itself at
`/api/v1/docs` (OpenAPI at `/api/v1/openapi.json`).

## Tokens

Make one on your **Account** page (click your name, top right) or with
`POST /tokens`. A token:

- acts as you, with your role or a lower one: a viewer token for a dashboard or
  an AI agent can only read;
- is shown once and stored only as a hash;
- can expire (`expires_days`), and can be revoked by you or an admin;
- shows when it was last used, and everything it changes is in the audit log as
  `Your Name (token its-name)`;
- never has more than your current role: if you're demoted, your tokens are too.

```bash
TOKEN=fwt_…
curl -H "Authorization: Bearer $TOKEN" https://fleetwright:8443/api/v1/me
```

Session cookies don't work on the API, so another site can't use a signed-in
browser to call it.

## Conventions

- **Errors** are always
  `{"error": {"code": "not_found", "message": "No such host", "errors": ["…"]}}`
  with the matching status: `invalid` 400 (every problem listed in `errors`),
  `unauthorized` 401, `forbidden` 403 (it says which role is needed),
  `not_found` 404, `conflict` 409, `rate_limited` 429.
- **Paging**: list endpoints take `limit` and `cursor` and return `next_cursor`,
  which is `null` on the last page. Pass it back to get the next page.
- **Unknown fields** in a request body are refused rather than ignored, so a
  typo can't quietly do nothing.
- **Times** are ISO 8601. A time without an offset counts as UTC.
- **Rate limit**: 600 requests a minute per token
  (`FLEETWRIGHT_API_RATE_PER_MIN`), in bursts of up to 120; past that, 429 with
  `Retry-After`.

## Runs

Starting a run returns its id at once:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -H "Idempotency-Key: nightly-$(date +%F)" https://fleetwright:8443/api/v1/runs -d '{
  "kind": "apply",
  "target": {"groups": [3], "exclude_tags": ["no-auto"]},
  "selection": {"mode": "kinds", "kinds": ["security"], "min_severity": "important"},
  "batch_percent": 10, "canary": true, "max_failures": 2, "reboot": "if_needed"}'
# {"run_id": 42}
```

- `kind` is `apply`, `reboot`, `scan`, `auto_off` (stop the hosts' own
  automatic updates) or `agent_update`.
- `selection` is `{"mode": "all"}` or `{"mode": "kinds", …}`.
- To install particular updates, use `"picked": {"<host id>": [{"name": "openssl"}]}`
  instead. They're pinned to the versions pending now, as on a host's page.
- **Idempotency-Key**: send the same key again (a retry after a timeout, say)
  and you get the first answer back, with `Idempotent-Replayed: true`, instead
  of a second run. Keys last a day. They work on `POST /runs`,
  `/runs/{id}/retry`, `/policies/{id}/run` and `/agents/update`.

Follow a run as it happens with Server-Sent Events:

```bash
curl -N -H "Authorization: Bearer $TOKEN" https://fleetwright:8443/api/v1/runs/42/events
# event: run   data: {"id": 42, "status": "running", …}
# event: task  data: {"id": 311, "host": "web-07", "status": "running", …}
# event: log   data: {"task_id": 311, "host": "web-07", "text": "12:01:07 ▸ apply\n…"}
# event: end   data: {"status": "done"}
```

## Endpoints

Generated from the code: each endpoint, the lowest role allowed, and what it does.

### Hosts

| Endpoint | Role | What it does |
|---|---|---|
| `GET /hosts` | Viewer | Hosts matching the hosts page's filters, with the count for each status. |
| `GET /hosts/{host_id}` | Viewer | One host: what it is, its counts, the policies that apply to it and hosts sharing its machine id. |
| `GET /hosts/{host_id}/updates` | Viewer | A host's pending updates (kind: all, security, kernel, held), most urgent first. |
| `GET /hosts/{host_id}/history` | Viewer | What FleetWright did to a host: package version changes and its recent tasks. |
| `POST /hosts` | Operator | Add agentless hosts ({name, address, port}) that FleetWright reaches over SSH with a stored key; each is scanned. |
| `PATCH /hosts/{host_id}` | Operator | Change a host's name, group, tags, "never install" list, and (SSH hosts) address, port and key. |
| `POST /hosts/tag` | Operator | Add tags to hosts. |
| `POST /hosts/move` | Operator | Move hosts to a group (or out of any). |
| `POST /hosts/scan` | Operator | Scan hosts for updates now (all hosts when none are given). |
| `POST /hosts/{host_id}/forget-host-key` | Admin | Clear a host's pinned SSH host key; the next connection pins whatever key it offers. |
| `DELETE /hosts/{host_id}` | Admin | Remove hosts and their history. Agents on them can no longer connect. |
| `POST /hosts/delete` | Admin | Remove hosts and their history. Agents on them can no longer connect. |

### Runs

| Endpoint | Role | What it does |
|---|---|---|
| `POST /runs` | Operator | Start a run on the target's hosts: install updates (all, by kind or picked), reboot, scan, |
| `GET /runs` | Viewer | Runs, newest first (running and paused ones first on the page), with their host counts. |
| `GET /runs/{run_id}` | Viewer | A run with its batches and every host's task. |
| `GET /runs/{run_id}/events` | Viewer | A run with its batches and every host's task. |
| `GET /tasks/{task_id}` | Viewer | One host's task in a run (or a scan): its status, full log, result and package changes. |
| `POST /runs/{run_id}/pause` | Operator | Pause a run: the batch that's running finishes, then nothing new starts. |
| `POST /runs/{run_id}/resume` | Operator | Resume a paused run. |
| `POST /runs/{run_id}/abort` | Operator | Abort a run: hosts already running finish their current step, the rest are skipped. |
| `POST /runs/{run_id}/retry` | Operator | Start a new run, with the same settings, on just the hosts that failed in this one. |

### Agents and enrolment

| Endpoint | Role | What it does |
|---|---|---|
| `GET /agents` | Admin | Enrolled agents, the agent version this server hands out, and the enrolment tokens. |
| `POST /enrolment-tokens` | Admin | Create an enrolment token, returned once with the install command to run on each host. |
| `DELETE /enrolment-tokens/{token_id}` | Admin | Revoke an enrolment token. Agents already enrolled with it keep working. |
| `POST /agents/update` | Admin | Update every agent that can update itself and differs from this server's, as one careful run. |

### Policies

| Endpoint | Role | What it does |
|---|---|---|
| `POST /policies/preview` | Viewer | What a policy with this target and selection would install if it ran now: hosts matched, |
| `GET /policies` | Viewer | Every auto-install policy, switched-on ones first. |
| `GET /policies/{policy_id}` | Viewer | One policy, with what it would install now and its recent runs. |
| `POST /policies` | Operator | Create a policy, or replace one's settings: which updates, which hosts, when, in what batches. |
| `PUT /policies/{policy_id}` | Operator | Create a policy, or replace one's settings: which updates, which hosts, when, in what batches. |
| `POST /policies/{policy_id}/enable` | Operator | Switch a policy on or off. |
| `POST /policies/{policy_id}/disable` | Operator | Switch a policy on or off. |
| `POST /policies/{policy_id}/run` | Operator | Run a policy straight away, outside its window, with its own settings. |
| `DELETE /policies/{policy_id}` | Operator | Delete a policy (its past runs stay). |

### Bookings

| Endpoint | Role | What it does |
|---|---|---|
| `GET /bookings` | Viewer | Booked installs: upcoming ones first, then those of the last two weeks. |
| `POST /bookings` | Operator | Book a one-off install for a window: everything, by kind, or picked updates pinned to their versions |
| `POST /bookings/{booking_id}/approve` | Admin | Approve a booked install that needs an admin's approval. |
| `POST /bookings/{booking_id}/cancel` | Operator | Cancel a booked install that hasn't started. |

`on_window_close` is `finish_started` (the default: hosts already running finish, no new host starts), `carry_on`,
or the legacy alias `stop`, which behaves exactly like `finish_started` — stopping an install in progress isn't safe.

### Overview and audit

| Endpoint | Role | What it does |
|---|---|---|
| `GET /overview` | Viewer | The fleet at a glance: totals, groups, recent runs, hosts updated per day, OS mix and what needs attention. |
| `GET /audit` | Admin | The audit log, newest first: who changed what. |

### Groups

| Endpoint | Role | What it does |
|---|---|---|
| `GET /groups` | Viewer | Host groups, with how many hosts each has. |
| `POST /groups` | Admin | Add a group, or rename one. |
| `PUT /groups/{group_id}` | Admin | Add a group, or rename one. |
| `DELETE /groups/{group_id}` | Admin | Delete a group; its hosts stay, ungrouped. |

### SSH keys

| Endpoint | Role | What it does |
|---|---|---|
| `GET /ssh-keys` | Admin | Stored SSH keys (public halves only) and how many hosts use each. |
| `POST /ssh-keys` | Admin | Store an SSH key for agentless hosts: paste a private key, or leave it out to generate an ed25519 one. |
| `DELETE /ssh-keys/{key_id}` | Admin | Delete a stored SSH key. Hosts that used it need another. |

### Users

| Endpoint | Role | What it does |
|---|---|---|
| `GET /users` | Admin | Everyone with an account, their role and last sign-in. |
| `POST /users` | Admin | Add someone; returns a single-use setup link (valid 72 hours) for them to choose a password. |
| `PATCH /users/{user_id}` | Admin | Change someone's role. There's always at least one admin. |
| `POST /users/{user_id}/setup-link` | Admin | A new single-use setup link for someone (to set or reset their password). |
| `DELETE /users/{user_id}` | Admin | Remove someone's account (and their API tokens). |

### Notifications

| Endpoint | Role | What it does |
|---|---|---|
| `GET /notifications` | Admin | Notification channels (secrets left out), the events they can choose from and the unreachable wait. |
| `POST /notifications/channels` | Admin | Add a notification channel (email, webhook or ntfy), or change one. A blank secret keeps the stored one. |
| `PUT /notifications/channels/{channel_id}` | Admin | Add a notification channel (email, webhook or ntfy), or change one. A blank secret keeps the stored one. |
| `POST /notifications/channels/{channel_id}/test` | Admin | Send a test message through a channel now; any error is returned and shown on the channel. |
| `POST /notifications/channels/{channel_id}/enable` | Admin | Turn a channel on or off. |
| `POST /notifications/channels/{channel_id}/disable` | Admin | Turn a channel on or off. |
| `DELETE /notifications/channels/{channel_id}` | Admin | Delete a notification channel. |
| `PUT /notifications/options` | Admin | How long a host must be unreachable before it's reported (1 to 10080 minutes). |

### Backups

| Endpoint | Role | What it does |
|---|---|---|
| `GET /backups` | Admin | The last backup and the secret key's state at this process's start. |

### HTTPS

| Endpoint | Role | What it does |
|---|---|---|
| `GET /https` | Admin | The certificate FleetWright serves (names, expiry, fingerprint, the pin agents use). |
| `POST /https/certificate` | Admin | Install your own certificate (with any chain) and key; agents get it first, then FleetWright restarts. |
| `POST /https/regenerate` | Admin | Make a new self-signed certificate (with extra names); agents get it first, then FleetWright restarts. |

### API tokens

| Endpoint | Role | What it does |
|---|---|---|
| `GET /tokens` | Viewer | Your API tokens (an admin can ask for everyone's): name, role, expiry and when each was last used. |
| `POST /tokens` | Viewer | Create an API token for yourself, with your role or a lower one. The token is returned only this once. |
| `DELETE /tokens/{token_id}` | Viewer | Revoke one of your API tokens (an admin can revoke anyone's). |

## Testing against a real install

`tests/integration/api_smoke.py <url> <admin token>` drives a test install
through the API and checks every answer: tokens and roles, hosts, runs with
idempotency and the event stream, policies, bookings, admin endpoints, errors,
paging and the rate limit. It needs SSH hosts that answer; the load test's SSH
farm works (`tests/load/README.md`). It changes data, so only run it against a
test install.
