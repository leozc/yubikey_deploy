# GPG through a forwarded gpg-agent

The remote `gpg` talks to the local gpg-agent through its *extra* socket, a
restricted socket meant for exactly this. Keys, the card, the PIN cache and
the pinentry all stay local. Nothing secret is copied to the remote except
the public key.

## 1. Local side

A forwarded request prompts through the local agent's pinentry, and there's
no terminal for it to use. Install a GUI pinentry:

```sh
brew install pinentry-mac
echo "pinentry-program $(brew --prefix)/bin/pinentry-mac" >> ~/.gnupg/gpg-agent.conf
gpgconf --kill gpg-agent            # restarts on next use
gpgconf --list-dirs agent-extra-socket
```

## 2. Socket forward

Find the remote's standard agent socket, e.g. `/run/user/1000/gnupg/S.gpg-agent`:

```sh
ssh devbox gpgconf --list-dirs agent-socket
```

Then forward the local extra socket onto it. Use absolute paths:

```
Host devbox
  RemoteForward /run/user/1000/gnupg/S.gpg-agent /Users/you/.gnupg/S.gpg-agent.extra
```

The remote sshd needs `StreamLocalBindUnlink yes`, so a stale socket file is
replaced instead of making the forward fail. The forward lives as long as the
ssh session that created it. When several sessions are open, the newest one
has bound the path.

## 3. Remote side

First check `ssh devbox gpg -K`. If the remote has secret keys of its own,
routing it to the local agent hides them; stop and ask.

```sh
gpg --export KEYID | ssh devbox gpg --import
ssh devbox 'echo "FULL_FINGERPRINT:6:" | gpg --import-ownertrust'
ssh devbox 'echo no-autostart >> ~/.gnupg/gpg.conf'
ssh devbox 'systemctl --user mask --now gpg-agent.socket gpg-agent-extra.socket \
  gpg-agent-ssh.socket gpg-agent-browser.socket gpg-agent.service'
```

Why mask: on systemd distributions, socket units listen on the same path the
forward uses and can re-create it. `no-autostart` stops gpg from spawning a
local agent when the forward is absent. Without it you'd get a confusing
empty keyring instead of a clear error.

## 4. Verify

```sh
ssh devbox 'echo test | gpg --clearsign -u KEYID | gpg --verify'
```

A pinentry dialog appears on the Mac, and the result should be
`Good signature`. The line `problem with fast path key listing: Forbidden` is
the extra socket declining a command it doesn't allow; it's harmless.

## 5. Copying keys onto the card

Ask the user first. It writes key material to hardware, needs their
passphrase and the card's Admin PIN, and some agent harnesses require
explicit approval for it.

**What "copy" means.** `keytocard` writes the key to the card immediately.
Answering *no* to "Save changes?" keeps the disk copy. But an agent that has
both a disk copy and a card copy signs with the disk copy, so on this machine
(and for requests forwarded to it) the card isn't used and no touch or card
PIN is needed. The card copy serves other machines. To make this machine use
the card, remove the disk copy afterwards, and only with an offline backup:
that step is irreversible without one. `gpg -K` shows `sec>`/`ssb>` for
card-backed keys.

**Back up the key files first.** They're passphrase-protected already, so a
file copy adds no exposure:

```sh
H=$(gpgconf --list-dirs homedir); B="$H/private-keys-v1.d.bak-$(date +%Y%m%d)"
mkdir -m 700 "$B"
for g in $(gpg -K --with-keygrip --with-colons KEYID | awk -F: '$1=="grp"{print $10}'); do
  cp -p "$H/private-keys-v1.d/$g.key" "$B/"
done
(cd "$H/private-keys-v1.d" && shasum -a 256 $(cd "$B" && ls *.key)) > "$B/SHA256SUMS"
```

**Slots.** 1 = Signature, 2 = Encryption, 3 = Authentication. A primary key
with sign capability can go to slot 1. Card key attributes adjust themselves
to the key size; RSA-2048 slots became RSA-4096 during `keytocard` on a
YubiKey 5 (OpenPGP 3.4).

**Scripted run** for the common layout, a primary key with sign capability
plus one encryption subkey. pinentry asks for the key passphrase and the
Admin PIN, possibly once per key:

```sh
printf '%s\n' keytocard y 1 "key 1" keytocard 2 quit n y |
  gpg --no-tty --command-fd 0 --status-fd 3 --edit-key KEYID 3>status.log
```

`--no-tty` is required; without it gpg fails with `cannot open '/dev/tty'`.
Afterwards, `status.log` shows the prompt order: `keyedit.keytocard.use_primary`,
`cardedit.genkeys.storekeytype`, `keyedit.save.okay`. For any other key
layout, check that order first, or have the user run `gpg --edit-key`
interactively.

**Check the result:**

```sh
gpg --card-status | grep -E 'Signature key|Encryption key'   # fingerprints now present
(cd "$H/private-keys-v1.d" && shasum -a 256 -c "$B/SHA256SUMS")   # OK = disk copy intact
```

If the checksums fail, the disk copy was replaced by stubs. Copy the files
back from `$B`.

**Card hygiene.** The factory PINs are 123456 (user) and 12345678 (admin).
Change them with `ykman openpgp access change-pin` and `change-admin-pin`.
Optionally require a touch per signature:
`ykman openpgp keys set-touch sig on`.
