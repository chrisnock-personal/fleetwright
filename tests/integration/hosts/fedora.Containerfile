# A systemd Fedora 44 "host" for the integration tests.
FROM registry.fedoraproject.org/fedora:44
# systemd-resolved would replace the container engine's DNS (Docker's) with its own stub,
# and the host couldn't find FleetWright by name.
RUN dnf -q -y install systemd python3 python3-websockets curl >/dev/null && dnf clean all \
 && systemctl mask systemd-resolved.service \
 && rm -f /etc/machine-id
COPY boot.sh /boot.sh
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/bin/sh", "/boot.sh"]
