#!/bin/zsh
TUNNEL_DESK_ROOT="${0:A:h}"
exec python3 "$TUNNEL_DESK_ROOT/main.py" --install-service --open
