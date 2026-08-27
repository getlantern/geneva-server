#!/bin/sh
# Start two echo listeners in the shared network namespace: 8080 is the "proxy"
# the sidecar steers; 9090 is an unrelated service used to prove the steering is
# scoped and never touches other ports.
set -eu
/usr/local/bin/echo -addr :9090 -size 65536 &
exec /usr/local/bin/echo -addr :8080 -size 1048576
