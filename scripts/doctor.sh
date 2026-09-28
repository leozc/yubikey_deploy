#!/bin/sh
# Read-only preflight for using a local security key from HOST.
# Checks this Mac and HOST for what each piece (sk agent, FIDO relay, gpg
# forwarding, X11 PIN UI) needs, and prints ok/warn/fail lines.
# Usage: doctor.sh HOST [RELAY_PYTHON]
#   RELAY_PYTHON: python that has fido2 installed (default: python3)
HOST="${1:?usage: doctor.sh HOST [RELAY_PYTHON]}"
PY="${2:-python3}"
ok() { echo "ok    $*"; }
warn() { echo "warn  $*"; }
fail() { echo "fail  $*"; }

echo "== local"
ssh -V 2>&1 | sed 's/^/info  /'
if command -v fido2-token >/dev/null; then
  n=$(fido2-token -L 2>/dev/null | wc -l | tr -d ' ')
  [ "$n" -gt 0 ] && ok "$n FIDO device(s) attached" || fail "no FIDO device attached"
else
  warn "fido2-token not installed (brew install libfido2) - cannot list FIDO devices"
fi
"$PY" -c "import fido2.hid.macos" 2>/dev/null && ok "python-fido2 importable by $PY" \
  || warn "python-fido2 missing for $PY (needed by fido-relay-local.py)"

cfg=$(ssh -G "$HOST" 2>/dev/null)
fa=$(echo "$cfg" | awk '$1=="forwardagent"{print $2}')
case "$fa" in
  no | "") warn "ForwardAgent is off for $HOST (sk agent not forwarded)" ;;
  yes) warn "ForwardAgent yes forwards your default agent; prefer an explicit socket path" ;;
  *)
    case "$fa" in "~/"*) sock="$HOME/${fa#"~/"}" ;; *) sock="$fa" ;; esac
    if [ -S "$sock" ]; then
      ok "ForwardAgent $fa (socket present)"
      SSH_AUTH_SOCK="$sock" ssh-add -l 2>&1 | sed 's/^/info    agent key: /'
    else
      fail "ForwardAgent $fa but no socket there (start sk-agent.sh)"
    fi ;;
esac
echo "$cfg" | awk '$1=="remoteforward"{print "info  remoteforward " $2 " <- " $3}'

if command -v gpgconf >/dev/null; then
  # gpgconf doesn't report pinentry-program, so read gpg-agent.conf itself.
  pe=$(awk '$1=="pinentry-program"{print $2}' "$(gpgconf --list-dirs homedir)/gpg-agent.conf" 2>/dev/null)
  case "$pe" in
    *mac* | *qt* | *gnome* | *gtk*) ok "gpg pinentry: $pe" ;;
    *) warn "gpg pinentry '${pe:-default}' may need a tty; forwarded requests need a GUI pinentry" ;;
  esac
  ok "gpg extra socket: $(gpgconf --list-dirs agent-extra-socket)"
fi
[ -d /Applications/Utilities/XQuartz.app ] && ok "XQuartz installed (ssh -X for PIN UI)" \
  || warn "XQuartz not installed (needed only for a visible remote browser)"

echo "== remote: $HOST"
ssh -T -x -o BatchMode=yes -o ForwardAgent=no -o ClearAllForwardings=yes "$HOST" sh -s <<'EOF'
ok() { echo "ok    $*"; }
warn() { echo "warn  $*"; }
fail() { echo "fail  $*"; }
echo "info  $(uname -sr)"
[ -c /dev/uhid ] && ok "/dev/uhid present" || fail "/dev/uhid missing (modprobe uhid)"
sudo -n true 2>/dev/null && ok "passwordless sudo" \
  || warn "no passwordless sudo; the relay needs 'sudo -n' for its command (sudoers NOPASSWD rule)"
command -v python3 >/dev/null && ok "python3 $(python3 -V 2>&1 | cut -d' ' -f2)" || fail "python3 missing"
for p in /usr/local/bin/fido-uhid-relay.py "$HOME/.local/bin/fido-uhid-relay.py"; do
  [ -x "$p" ] && ok "relay installed: $p"
done
if sudo -n true 2>/dev/null; then
  sudo -n sshd -T 2>/dev/null | awk '
    $1=="allowagentforwarding"       {print ($2=="yes"?"ok    ":"fail  ") "sshd AllowAgentForwarding " $2}
    $1=="allowstreamlocalforwarding" {print ($2!="no"?"ok    ":"fail  ") "sshd AllowStreamLocalForwarding " $2}
    $1=="streamlocalbindunlink"      {print ($2=="yes"?"ok    ":"warn  ") "sshd StreamLocalBindUnlink " $2 " (gpg socket forward)"}
    $1=="x11forwarding"              {print ($2=="yes"?"ok    ":"warn  ") "sshd X11Forwarding " $2}'
fi
command -v xauth >/dev/null && ok "xauth present" || warn "xauth missing (ssh -X won't work)"
for b in google-chrome chromium chromium-browser; do
  command -v $b >/dev/null && echo "info  browser: $b"
done
command -v node >/dev/null && ok "node $(node -v) (webauthn-test.mjs)" || warn "node missing (webauthn-test.mjs)"
command -v fido2-token >/dev/null && ok "fido2-token present" || warn "fido2-token missing (apt install fido2-tools)"
if command -v gpg >/dev/null; then
  grep -qx no-autostart "$HOME/.gnupg/gpg.conf" 2>/dev/null && ok "gpg no-autostart set" \
    || warn "gpg.conf lacks no-autostart (a local agent can shadow the forwarded one)"
  [ -n "$(gpg -K 2>/dev/null)" ] && warn "remote has its own gpg secret keys; forwarding would hide them"
  if command -v systemctl >/dev/null; then
    s=$(systemctl --user is-enabled gpg-agent.socket 2>/dev/null)
    [ "$s" = masked ] && ok "systemd gpg-agent.socket masked" \
      || warn "systemd gpg-agent.socket is '$s' (can re-create the socket the forward uses)"
  fi
  echo "info  remote gpg agent socket: $(gpgconf --list-dirs agent-socket)"
fi
EOF
