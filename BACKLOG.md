# Backlog

The work lives in [GitHub issues](https://github.com/chrisnock-personal/fleetwright/issues): this is an index of the open ones, in order.
Bugs are issues too, closed by the commit that fixes them.

## Next up ([label: next up](https://github.com/chrisnock-personal/fleetwright/issues?q=is%3Aopen+label%3A%22next+up%22)), in this order (agreed 2026-11-10)

1. [#6](https://github.com/chrisnock-personal/fleetwright/issues/6) Detect unattended-upgrades and dnf-automatic
2. [#7](https://github.com/chrisnock-personal/fleetwright/issues/7) Load test
3. [#8](https://github.com/chrisnock-personal/fleetwright/issues/8) Notifications (email, webhook, ntfy)
4. [#9](https://github.com/chrisnock-personal/fleetwright/issues/9) Backups and secret-key rotation
5. [#10](https://github.com/chrisnock-personal/fleetwright/issues/10) Agent self-update

## Features

- [#11](https://github.com/chrisnock-personal/fleetwright/issues/11) "As soon as released" policies for critical updates
- [#12](https://github.com/chrisnock-personal/fleetwright/issues/12) Show OS-level holds (apt-mark, dnf versionlock)
- [#13](https://github.com/chrisnock-personal/fleetwright/issues/13) Ubuntu security severity from USN or pro data
- [#14](https://github.com/chrisnock-personal/fleetwright/issues/14) Show Ubuntu phased updates
- [#15](https://github.com/chrisnock-personal/fleetwright/issues/15) Known host keys when adding SSH hosts
- [#16](https://github.com/chrisnock-personal/fleetwright/issues/16) A narrower agentless mode
- [#17](https://github.com/chrisnock-personal/fleetwright/issues/17) Full REST API with the same roles as the UI, for headless use
- [#28](https://github.com/chrisnock-personal/fleetwright/issues/28) CLI (`fw`) wrapping the API, for the command line and AI agents (needs #17)
- [#18](https://github.com/chrisnock-personal/fleetwright/issues/18) Snap and Flatpak
- [#19](https://github.com/chrisnock-personal/fleetwright/issues/19) Test and document Debian, RHEL, Rocky and Alma

## Fixes and tidy-ups

- [#20](https://github.com/chrisnock-personal/fleetwright/issues/20) Relabel or remove "Stop at once" when a window closes
- [#21](https://github.com/chrisnock-personal/fleetwright/issues/21) Show agents that missed a certificate change, with the re-enrol command
- [#22](https://github.com/chrisnock-personal/fleetwright/issues/22) Move the sign-in throttle and setup code to Postgres
- [#23](https://github.com/chrisnock-personal/fleetwright/issues/23) Use a real migration tool instead of schema.sql
- [#24](https://github.com/chrisnock-personal/fleetwright/issues/24) Postgres over TLS when the database is on another host
- [#25](https://github.com/chrisnock-personal/fleetwright/issues/25) Integration tests in CI (Ubuntu/Fedora containers, pip-audit, gitleaks)
- [#26](https://github.com/chrisnock-personal/fleetwright/issues/26) Show when an agent is older than the server

## Docs and publishing

- [#27](https://github.com/chrisnock-personal/fleetwright/issues/27) Publish the agent to PyPI as fleetwright-agent
