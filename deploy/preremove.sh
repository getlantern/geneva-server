#!/bin/sh
# Stop the sidecar before its binary is removed so it tears down its own
# nftables table on the way out. Leaving the table behind would keep steering
# the proxy's traffic into a queue with no reader; the kernel's queue verdict
# for an absent listener is to drop, so the proxy would go dark.
#
# The account is deliberately left in place: an upgrade removes and reinstalls,
# and dropping the user mid-upgrade would orphan the running unit's identity.
set -e

if [ -d /run/systemd/system ]; then
    deb-systemd-invoke stop geneva-server.service >/dev/null 2>&1 || true
fi
