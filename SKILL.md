---
name: yubikey-deploy
description: Use a YubiKey or other FIDO2 security key plugged into a Mac from a remote Linux machine over SSH. Covers SSH/git auth through a forwarded FIDO (ed25519-sk/ecdsa-sk) agent, WebAuthn/U2F/passkeys in Chrome on the remote (headless, or visible over X11 for the PIN prompt) through a CTAPHID-over-SSH relay to a virtual HID device, and GPG signing through a forwarded gpg-agent, including copying keys onto the card. Use this whenever someone wants their local security key to work on a devbox, VM, cloud workstation or other SSH host; sees "agent refused operation", "device not found" or FIDO_ERR_* errors with an sk key; needs security-key or passkey login in a remote or headless browser; wants gpg-agent forwarding; or asks why a touch or PIN prompt never shows up.
---

# Use a local security key from a remote Linux host

The key stays plugged into the local Mac. Three independent channels reach
the remote host. Set up only the ones the user needs, because each one
exposes the key to that host in a different way.

| Need on the remote | Mechanism | Human involvement |
|---|---|---|
| ssh/git to other hosts with an sk key | dedicated FIDO ssh-agent, forwarded with `ForwardAgent <socket>` | touch |
| WebAuthn/U2F/passkeys in a browser | `fido-relay-local.py` → ssh → `fido-uhid-relay.py`, which creates a virtual FIDO HID device | touch; PIN only in a visible browser |
| GPG sign/decrypt | local gpg-agent's *extra* socket, forwarded with `RemoteForward` | passphrase or card PIN in a GUI pinentry |

Scripts live in `scripts/`. Examples use `devbox` for the remote host.
Supported sides: macOS locally (the relay uses IOKit through python-fido2);
Linux remotely (the relay uses `/dev/uhid`).

## Ground rules

- **Secrets never pass through you.** PINs and passphrases go into GUI
  prompts (`scripts/macos-askpass`, pinentry-mac, Chrome's own dialog) that
  hand the value straight to the program. Don't ask the user to type one into
  the chat or a command line, and don't pipe one into a tool.
- **Ask before anything persistent or outward-facing.** That covers writing
  keys onto the card (`keytocard`), registering keys with GitHub or any other
  service, and installing login services (LaunchAgents, systemd units). These
  are hard to undo or change what other systems trust, and some agent
  harnesses refuse them without explicit approval.
- **Touches have a ~30-second window.** The key blinks, then gives up. A
  request that starts on the remote gives no visible cue locally, so set up
  notifications (Step 1d, Step 2) before asking the user to touch. Tell them
  *before* you start a command that needs a touch, not after.
- **Don't burn PIN retries.** Before retrying after `PIN incorrect`, check
  `ykman fido info`. Three wrong PINs in a row require re-inserting the key.
  Eight in total lock the FIDO applet, and a reset wipes every FIDO
  credential on the key.
- **Automation must never wait on a human.** Anything unattended on the
  remote (git over SSH, CI, agents) should use on-disk keys. See Step 4.

## Step 0: Preflight

```sh
scripts/doctor.sh devbox [path/to/venv/bin/python]
```

It's read-only. It checks the attached FIDO devices, the effective
`ForwardAgent`/`RemoteForward` for the host, the gpg pinentry, and XQuartz on
the Mac. On the remote it checks `/dev/uhid`, `sudo -n`, the sshd forwarding
options, xauth, browsers, node, and whether gpg-agent is shadowed. Fix
`fail` lines before you continue.

## Step 1: SSH with a FIDO key

**1a. Check that this authenticator can sign for the key.** An sk key file is
only a handle to a credential that lives on the authenticator that enrolled
it. With a different key plugged in, the agent still lists the key, but every
signature fails. Test locally first:

```sh
echo test > /tmp/m && ssh-keygen -v -Y sign -n file -f ~/.ssh/id_ed25519_sk /tmp/m
```

`FIDO_ERR_NO_CREDENTIALS` / `device not found` means the key was enrolled on a
different authenticator. Over forwarding, the same failure shows up as
`agent refused operation`.

**1b. Enroll a key on this authenticator if needed.** On CTAP 2.0 keys with a
PIN set (e.g. YubiKey 5.2.x), enrollment needs the PIN even for non-resident
keys. Without a tty, ssh-keygen can only ask through askpass:

```sh
SSH_ASKPASS=scripts/macos-askpass SSH_ASKPASS_REQUIRE=force \
  ssh-keygen -t ed25519-sk -N "" -C "<label>" -f ~/.ssh/id_ed25519_sk </dev/null
```

The user enters the PIN in the dialog and then touches the key right away.
`-v` output shows the stages. A first `FIDO_ERR_PIN_REQUIRED`, logged as
"incorrect passphrase supplied", is the normal retry before the PIN prompt.
`FIDO_ERR_ACTION_TIMEOUT` means no touch arrived in time. Use `ecdsa-sk` if
the firmware lacks Ed25519.

**1c. Run a dedicated agent.** `scripts/sk-agent.sh ~/.ssh/id_ed25519_sk`
runs an ssh-agent on `~/.ssh/sk-agent.sock` that holds only FIDO keys.
Forwarding your main agent (or a password manager's) would hand the remote
every key in it. With sk keys only, each use still needs a physical touch
here, so even root on the remote can't sign silently. Use an ssh-agent built
with FIDO support (Homebrew `openssh` works). Point `SSH_AGENT_BIN` at it if
another ssh-agent comes first on PATH.

**1d. Turn on touch notifications.** Start the agent with
`SSH_ASKPASS=<path>/macos-askpass SSH_ASKPASS_REQUIRE=force`. ssh-agent then
posts "Confirm user presence for key …" whenever a forwarded request is
waiting for a touch. Without it, requests from the remote time out silently.

**1e. Forward exactly that socket.**

```
Host devbox
  ForwardAgent ~/.ssh/sk-agent.sock
```

An explicit path forwards this agent no matter what `SSH_AUTH_SOCK` or
`IdentityAgent` point at. Confirm the effective value with
`ssh -G devbox | grep -i forwardagent`. First match wins, so a broader
`Host` block above can shadow yours. Keep Host patterns lowercase: a
`Host MyBox` block did not apply to `ssh mybox` in testing.

**1f. Verify.** `ssh devbox ssh-add -l` should list the sk key. Then have the
remote sign something (`ssh devbox 'ssh -T git@github.com'` if GitHub has the
key; see Step 4) and expect a notification plus a touch.

Long-lived remote processes (tmux panes, daemons) keep the `SSH_AUTH_SOCK` of
the session that started them. They lose the agent when that session ends.

## Step 2: WebAuthn in a browser on the remote (FIDO relay)

Browsers need the key to appear as a local FIDO HID device, which agent
forwarding can't provide. USB/IP would need a server on macOS, which doesn't
exist natively. Instead, `fido-relay-local.py` opens the key on the Mac
(shared, so the Mac keeps using it) and streams raw 64-byte CTAPHID reports
over ssh. On the remote, `fido-uhid-relay.py` replays them into a virtual
device created through `/dev/uhid`. Read `references/relay-internals.md`
before changing either script.

1. **Remote half:** it needs root for `/dev/uhid`, and ssh gives it no tty,
   so it runs with `sudo -n`. Install it root-owned, and add a narrow
   `NOPASSWD` sudoers rule for that path if the user lacks passwordless sudo:
   ```sh
   scp scripts/fido-uhid-relay.py devbox:/tmp/ && ssh devbox 'sudo install -m 755 /tmp/fido-uhid-relay.py /usr/local/bin/'
   ```
2. **Local half:**
   ```sh
   python3 -m venv ~/.local/share/yubikey-deploy/venv
   ~/.local/share/yubikey-deploy/venv/bin/pip install fido2
   ~/.local/share/yubikey-deploy/venv/bin/python scripts/fido-relay-local.py devbox --vid 1050
   ```
   It runs in the foreground; Ctrl-C removes the device. `--vid` picks a
   vendor (1050 = Yubico). It posts "devbox is waiting" when a remote request
   needs a touch. The relay's ssh session carries no agent, X11 or
   RemoteForward, so it doesn't interfere with Steps 1 and 3.
3. **Verify, no touch needed:** `ssh devbox fido2-token -L` (from the
   `fido2-tools` package) lists the relay device. `fido2-token -I /dev/hidrawN`
   returns the real key's firmware and versions.
4. **Headless Chrome:**
   `scp scripts/webauthn-test.mjs devbox:/tmp/ && ssh devbox node /tmp/webauthn-test.mjs`
   The user touches twice. The result should be `{"ok":true,...}`. This covers
   touch-only flows: security-key 2FA, `userVerification: "discouraged"`.
5. **Passkeys and PIN flows need a visible browser.** Headless Chrome has
   nowhere to show its PIN dialog, so UV-required requests can't finish.
   Forward X11: XQuartz locally, and `X11Forwarding yes` plus `xauth` on the
   remote.
   ```sh
   ssh -X devbox node /tmp/webauthn-test.mjs --gui      # try -Y if Chrome refuses untrusted X11
   ```
   Chrome's window opens on the Mac. The user clicks the button, enters the
   FIDO PIN in Chrome's dialog and touches the key. The result should show
   `uvCreate` and `uvGet` true. For real use, `ssh -X devbox google-chrome`.

Any process on the remote that can open the hidraw node can request
operations while the relay runs. Each one still needs a touch, and a PIN for
UV. Stop the relay when it isn't needed.

## Step 3: GPG through the forwarded agent

Read `references/gpg.md`. It covers the socket forward, remote gpg
configuration, verification, and copying keys onto the card. The facts that
trip people up:

- Forwarded requests prompt through the *local* agent's pinentry. A
  terminal pinentry (`pinentry-curses`, the Homebrew default) has no tty to
  use, so switch to `pinentry-mac`.
- On the remote, `no-autostart` plus masked systemd `gpg-agent*` units keep
  a local agent from taking over the forwarded socket. Skip this if the
  remote has secret keys of its own.
- "Copy to card" (`keytocard`, then quit *without* saving) keeps the disk
  key. But an agent with both copies signs with the disk copy, so the local
  machine and forwarded requests won't touch the card. Say so before doing
  it, and back up the key files first.

## Step 4: Keep automation human-free

A forwarded sk agent is offered to every host the remote connects to. An
unattended job that reaches GitHub over SSH will then block on a touch nobody
sees. Pin such destinations to an on-disk key on the remote:

```
Host github.com
  IdentityFile ~/.ssh/id_ed25519
  IdentitiesOnly yes
```

`IdentitiesOnly yes` stops ssh from offering the agent's keys. Check it with
`ssh -v -T git@github.com 2>&1 | grep -E 'Offering|Authenticated'`: only the
file key should be offered. Also check the git remotes, because HTTPS remotes
with a token never use SSH. The disk key must be registered as an
*authentication* key; GitHub tracks signing keys separately.

## Step 5: Keeping it running (the user's call)

`sk-agent.sh` and `fido-relay-local.py` are foreground processes. Starting
them at login (e.g. a LaunchAgent with `KeepAlive`, a `ThrottleInterval`,
and the `SSH_ASKPASS` variables in `EnvironmentVariables`) is convenient. For
the relay it also means the remote can reach the key whenever the Mac is
awake. Lay out that tradeoff and let the user decide and install it. The
relay exits when ssh drops or the key is unplugged, so a `KeepAlive`
supervisor restarts it.

## Known pitfalls

| Symptom | Cause | Fix |
|---|---|---|
| `agent refused operation` on the remote; `ssh-add -l` lists the sk key | key enrolled on another authenticator, or the touch timed out | 1a local sign test; 1d notifications |
| `Key enrollment failed: invalid format` | a generic wrapper; `-v` shows the real error, often `FIDO_ERR_ACTION_TIMEOUT` after the PIN | touch right after entering the PIN |
| enrollment stalls or fails at the PIN step without a terminal | ssh-keygen can't prompt without a tty | `SSH_ASKPASS` + `SSH_ASKPASS_REQUIRE=force` |
| `Cannot forward agent socket path … No such file or directory` | the local sk agent isn't running | start `sk-agent.sh` |
| `unix_listener: path … too long for Unix domain socket` | socket paths are limited to ~104 bytes on macOS | keep `SK_AGENT_SOCK` short, e.g. under `~/.ssh/` |
| `ssh -G` shows the wrong ForwardAgent | an earlier `Host` block matched first, or pattern case | reorder blocks; lowercase patterns |
| gpg on the remote hangs or reports no pinentry | the local pinentry needs a tty | `pinentry-program …/pinentry-mac`, then `gpgconf --kill gpg-agent` |
| remote gpg can't see your secret key | a remote agent (systemd socket) owns the socket path | `no-autostart`, mask `gpg-agent*.socket` units, reconnect |
| `problem with fast path key listing: Forbidden` | the extra socket refuses some commands | harmless |
| Chrome on the remote doesn't see the key | the hidraw node is root-only (no seat, so no uaccess ACL) | the relay chowns it to `SUDO_UID`; run it through sudo |
| relay drops responses or hangs | the device isn't kept on a run loop, or reads go through `read_packet()` | keep the relay's continuous run loop |
| keytocard *moved* the key when you meant to copy | the save prompt was answered yes | restore `private-keys-v1.d/<keygrip>.key` from the backup |
| passkey login hangs in headless Chrome | UV needs Chrome's PIN dialog | Step 2.5: visible Chrome over X11 |
