#!/bin/sh
set -eu
for f in bv_user_ca.pub ssh_host_ed25519_key; do
    [ -s "/bv/$f" ] || { echo "brokered-target: /bv/$f missing" >&2; exit 1; }
done
install -m 644 /bv/bv_user_ca.pub      /etc/ssh/bv_user_ca.pub
install -m 600 /bv/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
