# A systemd Fedora 44 "host" for the integration tests.
FROM registry.fedoraproject.org/fedora:44
RUN dnf -q -y install systemd python3 python3-websockets curl >/dev/null && dnf clean all \
 && rm -f /etc/machine-id
COPY boot.sh /boot.sh
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/bin/sh", "/boot.sh"]
