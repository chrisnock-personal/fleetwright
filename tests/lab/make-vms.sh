#!/bin/bash
# Two throwaway test hosts for FleetWright on a libvirt machine: Ubuntu 24.04 and Fedora 44
# cloud images on the default NAT network, user fwadmin with passwordless sudo and the key
# ~/.ssh/fleetwright_test. Remove them with: tests/lab/make-vms.sh --remove
#
# Note: virt-install --cloud-init powers a VM off on its first reboot; start it again with
# virsh start. Later reboots behave normally.
set -euo pipefail
D=~/VMs/fleetwright-test
C="--connect qemu:///system"
UBUNTU=https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
FEDORA=https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2

if [ "${1:-}" = "--remove" ]; then
    for vm in fw-ubuntu fw-fedora; do
        virsh $C destroy $vm 2>/dev/null || true
        virsh $C undefine $vm --remove-all-storage 2>/dev/null || true
    done
    rm -rf "$D" ~/.ssh/fleetwright_test ~/.ssh/fleetwright_test.pub
    echo "Removed."
    exit 0
fi

mkdir -p "$D"; cd "$D"
[ -f ~/.ssh/fleetwright_test ] || ssh-keygen -q -t ed25519 -N '' -f ~/.ssh/fleetwright_test -C fleetwright-test
[ -f noble.img ] || curl -sSLo noble.img "$UBUNTU"
[ -f f44.qcow2 ] || curl -sSLo f44.qcow2 "$FEDORA"
setfacl -m u:qemu:x ~ ~/VMs && setfacl -m u:qemu:rx "$D"
PUB=$(cat ~/.ssh/fleetwright_test.pub)
for vm in fw-ubuntu:noble.img:ubuntu24.04 fw-fedora:f44.qcow2:fedora-unknown; do
    IFS=: read -r name base os <<<"$vm"
    virsh $C dominfo "$name" >/dev/null 2>&1 && { echo "$name exists"; continue; }
    qemu-img create -q -f qcow2 -F qcow2 -b "$D/$base" "$D/$name.qcow2" 12G
    cat > "$D/$name-user-data" <<EOF
#cloud-config
hostname: $name
users:
  - name: fwadmin
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys: ["$PUB"]
EOF
    virt-install $C --name "$name" --memory 1536 --vcpus 2 --import --disk "$D/$name.qcow2" \
        --osinfo "$os" --network network=default --cloud-init user-data="$D/$name-user-data" \
        --noautoconsole --graphics none
done
sleep 60
virsh $C net-dhcp-leases default
