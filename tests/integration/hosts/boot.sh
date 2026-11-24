#!/bin/sh
# Each test host gets its own machine id (containers from one image would share one, and
# FleetWright would rightly treat them as clones), then systemd starts.
python3 -c 'import uuid; print(uuid.uuid4().hex)' > /etc/machine-id
exec /sbin/init
