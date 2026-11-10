# Backlog

What's outstanding after v1 (2026-11-09), roughly in priority order. Bugs are tracked as
[GitHub issues](https://github.com/chrisnock-personal/fleetwright/issues), closed by the commit that fixes them.


## Next up (in this order, agreed 2026-11-10)

1. [ ] **Detect `unattended-upgrades` and `dnf-automatic`.** A stock Ubuntu
       install runs `unattended-upgrades`, which installs security updates by
       itself. If it runs during a FleetWright run, its changes are recorded
       as FleetWright's, because the change list is a before/after diff of
       installed versions. Detect both services in the scan, flag them on the
       host page (and in the overview's "Needs attention"), and offer to turn
       them off where FleetWright manages updates. *Small, about half a day;
       fixes the accuracy of the history on every Ubuntu host.*
2. [ ] **Load test.** A few hundred simulated agents against one gateway
       process, and a few hundred SSH targets in containers. Measure the host
       page and the policy preview, which loads every pending update for its
       hosts into Python (the first thing likely to slow down). Fix whatever
       it shows. *About a day plus fixes; needed before trusting it at scale.*
3. [ ] **Notifications** by email, webhook or ntfy: a run failed, a host is
       unreachable, a booking needs approval, a critical update appeared.
       *Without them a failed night-time policy run goes unnoticed until
       someone opens the dashboard.*
4. [ ] **Backups and secret-key rotation.** `pg_dump` on a schedule,
       encrypted with `age` to a key kept apart from the data, with a restore
       procedure. Support a previous `FLEETWRIGHT_SECRET_KEY` so stored SSH keys
       can be re-encrypted under a new one. *Closes the last open rows of the
       security review.*
5. [ ] **Agent self-update** through the gateway: the agent checks a SHA-256
       sent over its verified connection before replacing itself. *Matters
       once there are many agents.*

## Features

- [ ] **"As soon as released" policies:** install critical updates within N
      hours of a scan finding them, instead of in a fixed window.
- [ ] **Show OS-level holds** (`apt-mark showhold`, `dnf versionlock`). They
      are already collected by scans but not stored or shown.
- [ ] **Ubuntu severity.** Fill it in from the USN feed or `pro` data, so a
      "Critical only" policy means the same on Ubuntu as on Fedora.
- [ ] **Phased updates** on Ubuntu: say when an update is being held back by
      phasing, rather than just not listing it.
- [ ] **Known host keys when adding SSH hosts:** accept pasted
      `ssh-keyscan` output, to avoid trust-on-first-use.
- [ ] **A narrower agentless mode:** a root-owned copy of pkgops on the host,
      with sudo limited to it, instead of sudo for `python3`.
- [ ] **REST API** with tokens, for scripting and for Alfoir.
- [ ] **Snap and Flatpak** updates.
- [ ] **More distributions:** Debian, RHEL, Rocky and Alma probably work
      already; test them and say so.

## Fixes and tidy-ups

- [ ] "Stop at once" when a window closes behaves like "finish hosts already
      started", because stopping mid-install isn't safe. Relabel or remove it.
- [ ] Agents that were offline during a certificate change can't reconnect.
      Show those hosts, with the re-enrol command, on the HTTPS page.
- [ ] The sign-in throttle and setup code live in memory, so the web app is
      limited to one process. Move them to Postgres if it ever needs more.
- [ ] Use a real migration tool instead of the idempotent `schema.sql` once
      the schema starts changing in incompatible ways.
- [ ] Postgres over TLS when the database isn't on the same compose network.
- [ ] Integration tests in CI: the test stack against Ubuntu and Fedora
      containers with systemd, and `pip-audit` and `gitleaks`.
- [ ] A host page for agents should say when the agent version is older
      than the server's.

## Docs and publishing

- [ ] If the agent is published to PyPI, use the name `fleetwright-agent`
      (`fleetwright` is taken).
