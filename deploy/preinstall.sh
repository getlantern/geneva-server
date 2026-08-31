#!/bin/sh
# Create the unprivileged account the systemd unit runs as. The sidecar needs
# CAP_NET_ADMIN/CAP_NET_RAW, not root, so the unit sets User=geneva-server and
# systemd delivers the two capabilities as ambient — which only works if the
# account exists before the unit is started.
#
# Runs before the files are unpacked so the /etc/geneva-server group ownership
# in the package's file_info resolves.
set -e

if ! getent group geneva-server >/dev/null 2>&1; then
    addgroup --system geneva-server
fi

if ! getent passwd geneva-server >/dev/null 2>&1; then
    adduser --system --no-create-home --disabled-login \
        --ingroup geneva-server --shell /usr/sbin/nologin geneva-server
fi
