# Load test

Simulated agents, SSH hosts and a big synthetic fleet against one FleetWright
stack, with timings for the main pages and for runs. Nothing here touches a
package mirror or a real host.

| File | What it is |
|---|---|
| `fake_agents.py` | Hundreds of agents in one process: real enrolment and WebSocket protocol, made-up packages; they scan, apply and "reboot" (disconnect and come back with a new boot id) |
| `sshfarm/` | One Alpine container running an `sshd` per port, each a separate SSH host (`FW_SEED` = its port) with fake `apt-get`/`dpkg-query`/`apt-mark`, so the worker runs the real pkgops over real SSH |
| `fakepkgs.py` | The made-up package data both use: 400 packages a host, up to 150 pending, about 15% security |
| `seed.py` | Admin, enrolment token, SSH key and a policy; then SSH hosts, or thousands of synthetic hosts straight into the database |
| `measure.py` | Page timings (signed in, over HTTPS) and run timings |
| `check_preview.py` | Checks that the policy preview's SQL counts what `pkgops.select` would pick; **changes the data**, so only on a load-test database |

## Running it

On a machine with podman, from a copy of the repo with its own `.env`
(`FLEETWRIGHT_PUBLIC_URL=https://web:8443`, and its own volume names so it
can't touch a real install):

```bash
podman-compose -p fwload up -d --build
(cd tests/load && podman build -f sshfarm/Containerfile -t localhost/fw-sshfarm .)

# a helper: run a script from tests/load in the FleetWright image, on the stack's network
tool() { podman run --rm -i --network fwload_default --env-file .env -e POSTGRES_HOST=db \
           -v "$PWD/tests/load:/load:ro,Z" localhost/fleetwright:latest python "/load/$@"; }

tool seed.py base                                   # prints the token and the farm's key
podman run -d --name fw-sshfarm --network fwload_default \
  -e "AUTHORIZED_KEY=<public key from above>" localhost/fw-sshfarm 2200 300
tool seed.py ssh 300 fw-sshfarm 2200                # 300 SSH hosts, each scanned once

podman run -d --name fw-agents --network fwload_default -v "$PWD/tests/load:/load:ro,Z" \
  localhost/fleetwright:latest python -u /load/fake_agents.py \
  --server https://web:8443 --token load-test-enrol --count 500 --inventory-every 120
podman logs -f fw-agents                            # a status line every 10 s

tool measure.py pages 10
tool measure.py run apply both 100                  # apply everything, 100 hosts per batch
tool seed.py synthetic 5000                         # then measure the pages again
tool check_preview.py
```

Afterwards: `podman rm -f fw-agents fw-sshfarm; podman-compose -p fwload down -v`, and
remove the two images.

## Results, 2026-11-22

One web process, one worker (50 SSH tasks at a time), Postgres 16, all on the
PC (i7-14700F, WSL2).

**500 agents and 300 SSH hosts.** All 500 agents enrolled, connected and
scanned within a minute with no errors. With every agent sending an inventory
every 2 minutes (the default is 6 hours), about 5 a second, the web process
stayed under 4% CPU and 300 MB of memory and Postgres under 4% CPU. Restarting
the web process dropped all 500 and they all came back by themselves.

| Run over all 800 | Time |
|---|---|
| Scan (300 SSH hosts alone) | 10 s |
| Scan (all at once) | 12 s |
| Apply everything, 100 hosts per batch | 96 s, no failures |

The fake apply takes 3-8 s a host; real ones take minutes, so a real run is
bound by the hosts, not by FleetWright. A run moves to its next batch on the
worker's 5-second housekeeping tick, so each batch adds up to 5 s.

**Pages at 5,800 hosts and 377,000 pending updates**, median of 5, before and
after the fixes this test led to:

| Page | Before | After | Fix |
|---|---|---|---|
| Policy page (with its preview) | 1,411 ms | 83 ms | count in SQL instead of loading every pending update into Python |
| Hosts, search for a package | 435 ms | 26 ms | trigram indexes (`pg_trgm`); JIT off |
| Run page, 800 hosts | 140 ms | 11 ms | index on `package_changes.task_id` |
| Overview | 81 ms | 14 ms | totals from `hosts.pending_count` and partial indexes |
| Hosts list (25, 250 a page), host page, runs | 10-17 ms | same | |

Pages while a scan of all 800 hosts ran were within a few ms of these.

JIT (Postgres's query compiler, on by default) cost more than it saved: the
package search took 104 ms with it and 8 ms without, so FleetWright's
connections now turn it off.

The policy preview over broad selections (everything, or all bug fixes)
across 5,800 hosts still takes 0.3-0.6 s; security-only ones take under 120 ms.
