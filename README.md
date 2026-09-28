# yubikey-deploy

A [Claude Code](https://claude.com/claude-code) / Agent Skills skill for
using a YubiKey (or any FIDO2 security key) plugged into your Mac from a
remote Linux machine over SSH:

- **SSH / git:** a dedicated ssh-agent holds only your FIDO (`-sk`) keys and
  is forwarded to the host. Every use needs a touch, and a macOS notification
  tells you when one is waiting.
- **WebAuthn / passkeys in a remote browser:** a small relay streams raw
  CTAPHID reports over ssh into a virtual HID device (`/dev/uhid`) on the
  remote. Headless Chrome works for touch-only flows. For PIN flows, Chrome
  runs over `ssh -X`.
- **GPG:** your local gpg-agent is forwarded to the host. The skill also
  covers copying keys onto the card without losing the disk copy.

The key never leaves your machine, and nothing works without a physical
touch.

## Install

```sh
git clone https://github.com/leozc/yubikey_deploy ~/.claude/skills/yubikey-deploy
```

Then ask your agent something like *"make my YubiKey work on devbox, including
Chrome there"*. It starts with `scripts/doctor.sh <host>`, a read-only
preflight.

## Layout

| Path | Purpose |
|---|---|
| `SKILL.md` | the workflow the agent follows |
| `scripts/doctor.sh` | read-only preflight of the Mac and the remote |
| `scripts/sk-agent.sh` | dedicated FIDO-only ssh-agent on a fixed socket |
| `scripts/macos-askpass` | native dialog for PINs and touch notifications |
| `scripts/fido-relay-local.py` | Mac half of the WebAuthn relay (needs `pip install fido2`) |
| `scripts/fido-uhid-relay.py` | Linux half: virtual FIDO HID device via uhid (stdlib only) |
| `scripts/webauthn-test.mjs` | headless or `--gui` WebAuthn check on the remote |
| `references/gpg.md` | gpg-agent forwarding and copying keys onto the card |
| `references/relay-internals.md` | how and why the relay works |

## Requirements

- **Local:** macOS, an OpenSSH build with FIDO support (Homebrew `openssh`),
  Python 3 with `fido2` for the relay, XQuartz for PIN UI in a remote
  browser, and `pinentry-mac` for GPG.
- **Remote:** Linux with `/dev/uhid`, `sudo -n` for the relay command,
  Python 3, and sshd allowing agent and streamlocal forwarding (plus X11 for
  the PIN UI).

## Security notes

- The relay lets processes on the remote *request* FIDO operations while it
  runs. Every one still needs your touch, and user verification needs your
  PIN. Run it only while you need it.
- Keep unattended automation on the remote (CI, bots, git over SSH) on
  on-disk keys with `IdentitiesOnly yes`, so it never waits on a touch.
