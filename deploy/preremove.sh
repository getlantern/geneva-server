#!/bin/sh
# Stop the sidecar before its binary is removed so it tears down its own
# nftables table on the way out. Leaving the table behind would keep steering
# the proxy's traffic into a queue with no reader; the kernel's queue verdict
# for an absent listener is to drop, so the proxy would go dark.
set -e

# Only on real removal. dpkg also runs prerm with "upgrade" before unpacking a
# new version, and stopping there would leave the service down — nothing in the
# package starts it again, and the old process keeps steering happily until the
# installer restarts it, so an upgrade has no window to protect against.
case "$1" in
    remove | deconfigure)
        if [ -d /run/systemd/system ]; then
            # Failure is not propagated: prerm returning non-zero aborts the
            # removal and leaves a half-removed package, which is a worse state
            # than a service that would not stop. A unit that was never enabled
            # (or is already stopped) also lands here and is not an error.
            deb-systemd-invoke stop geneva-server.service >/dev/null 2>&1 || true
        fi
        ;;
esac
