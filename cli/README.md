# fw: FleetWright from the command line

`fw` drives a FleetWright server through its API, with an API token, so it can do
exactly what that token's role allows. It's built for people at a terminal and
for scripts, CI pipelines and AI agents: every command can answer in JSON, and
the exit codes are stable.

```bash
pipx install ./cli          # from a FleetWright checkout; Python 3.10+, no other dependencies
fw login --url https://fleetwright:8443
```

`fw login` asks for a token (make one on your Account page in FleetWright). If
the server's certificate is FleetWright's own self-signed one, it shows its
SHA-256 fingerprint to compare with **Settings → HTTPS**, then accepts only that
certificate from then on. The check happens before the token is sent, so a
different server never sees it. Use `--fingerprint` to pass the value from that page directly.
The token goes into the OS keyring when the `keyring` package is installed
(`pipx install './cli[keyring]'`), otherwise into `~/.config/fleetwright/cli.json`,
readable only by you. `FW_URL`, `FW_TOKEN` and `FW_FINGERPRINT` work without any
login, which is handy in CI.

## Examples

```bash
fw overview
fw hosts list --status security --group web
fw hosts show web-07
fw hosts add --key prod web-01 10.0.0.11
fw updates list web-07 --kind security
fw history web-07 --since 7d

fw run apply --group web --kinds security --batch 10% --canary --reboot if-needed --dry-run
fw run apply --group web --kinds security --batch 10% --canary --reboot if-needed --yes --wait
fw run apply web-07 --pick openssl,curl --yes
fw run watch 42
fw run abort 42

fw policies list
fw policies run 3 --wait
fw book web-07 --window '2026-11-12 22:00/23:30' --pin openssl,curl
fw bookings approve 7
fw audit
```

Hosts, groups and SSH keys can be given by name or number. Every command has
`--help`, with examples on the main ones (`fw help run`).

## For scripts and agents

- `--json` on any command prints the API's answer, with stable field names.
  `--jsonl` prints one object per line, for lists and for `fw run watch`.
  Messages go to stderr, so stdout stays parseable.
- Exit codes: **0** ok, **1** failed (including a run in which any host failed),
  **2** usage (or the server said the request was invalid), **3** not allowed by
  the token's role (or the certificate changed), **4** not found.
- Anything that changes hosts asks first, unless `--yes` is given. Without a
  terminal and without `--yes`, it refuses (exit 2) rather than guessing.
- `--dry-run` on `fw run …` shows what it would install now, the same count as
  the policy preview, and starts nothing.
- `fw run … --wait` blocks until the run ends and exits 1 if any host failed.
  Add `--follow` to see the hosts' output as it comes.
- Each run request carries an idempotency key, so a retried request can't start
  a second run. Give your own with `--idempotency-key` to make a whole retried
  job safe.

## Profiles and completion

`fw login --profile prod --url …` adds another server. Pick one with
`--profile prod` or `FW_PROFILE`, and list them with `fw profiles`.

```bash
eval "$(fw completion bash)"     # or zsh; fish: fw completion fish > ~/.config/fish/completions/fw.fish
```
