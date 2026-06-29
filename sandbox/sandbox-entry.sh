#!/usr/bin/env bash
set -euo pipefail
echo "=== ShieldPatch Sandbox ==="
echo "Container started at: $(date -u)"
echo "Mount point: /sandbox"
echo "Switch to user: su - tester"
echo "To snapshot: docker commit <container> shieldpatch/sandbox:before"
echo
exec tail -f /dev/null
