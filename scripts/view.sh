#!/usr/bin/env bash
# Serves the results viewer: ./scripts/view.sh [port]
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${1:-8000}
BIND=${ESE_VIEW_BIND:-127.0.0.1}

echo "results viewer: http://$BIND:$PORT/tools/viewer/"
exec python3 -m http.server "$PORT" --bind "$BIND" --directory "$ROOT"
