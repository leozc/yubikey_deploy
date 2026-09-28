#!/bin/sh
# Dedicated ssh-agent that holds only FIDO (sk) keys, on a fixed socket, so
# ssh_config can forward exactly this agent and nothing else:
#   Host devbox
#     ForwardAgent ~/.ssh/sk-agent.sock
# Every signature still needs a touch on the key plugged into this machine.
#
# Usage: sk-agent.sh [KEY ...]        (default: ~/.ssh/id_*sk*, minus .pub)
# Env:   SK_AGENT_SOCK   socket path (default ~/.ssh/sk-agent.sock)
#        SSH_AGENT_BIN   ssh-agent with FIDO support (default: first on PATH)
#        SSH_ASKPASS + SSH_ASKPASS_REQUIRE=force
#                        make the agent show "Confirm user presence" when a
#                        (forwarded) request is waiting for a touch
SOCK="${SK_AGENT_SOCK:-$HOME/.ssh/sk-agent.sock}"
AGENT="${SSH_AGENT_BIN:-$(command -v ssh-agent)}"
ADD="$(dirname "$AGENT")/ssh-add"
[ $# -gt 0 ] || set -- "$HOME"/.ssh/id_*sk*

rm -f "$SOCK"
"$AGENT" -D -a "$SOCK" &
pid=$!
trap 'kill $pid 2>/dev/null' TERM INT
i=0
while [ ! -S "$SOCK" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
for key in "$@"; do
  case "$key" in *.pub) continue ;; esac
  [ -f "$key" ] && SSH_AUTH_SOCK="$SOCK" "$ADD" "$key"
done
wait $pid
