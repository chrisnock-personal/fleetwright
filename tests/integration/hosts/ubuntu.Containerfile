# A systemd Ubuntu 24.04 "host" for the integration tests: the agent installs into it as on a server.
FROM docker.io/library/ubuntu:24.04
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      systemd systemd-sysv python3 curl ca-certificates unattended-upgrades >/dev/null \
 && printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' \
      > /etc/apt/apt.conf.d/20auto-upgrades \
 && rm -f /etc/machine-id
COPY boot.sh /boot.sh
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/bin/sh", "/boot.sh"]
