#!/bin/sh
# entrypoint.sh <first port> <count>; the client's public key comes in as AUTHORIZED_KEY.
set -eu
FIRST=${1:-2200}; COUNT=${2:-300}
mkdir -p /root/.ssh /var/lib/fakeapt && chmod 700 /root/.ssh
printf '%s\n' "$AUTHORIZED_KEY" > /root/.ssh/authorized_keys
cat > /etc/ssh/sshd_config <<CONF
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
MaxStartups 200:30:400
CONF
p=$FIRST; last=$((FIRST + COUNT - 1))
while [ $p -le $last ]; do
    /usr/sbin/sshd -o Port=$p -o "SetEnv=FW_SEED=$p" -o PidFile=/run/sshd-$p.pid
    p=$((p + 1))
done
echo "sshd on ports $FIRST-$last"
exec sleep infinity
