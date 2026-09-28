# FIDO relay internals

Read this before changing `fido-relay-local.py` or `fido-uhid-relay.py`.
Every detail below came from a failure or a verified behavior.

```
browser on remote ── /dev/hidrawN ── uhid ── fido-uhid-relay.py (root)
                                                  │ stdin/stdout: raw 64-byte reports
                                            ssh -T (no agent/X11/forwards)
                                                  │
                        security key ── IOKit ── fido-relay-local.py (Mac)
```

## Why this design

- **Browsers only talk to local HID devices.** Agent forwarding carries SSH
  signatures, not CTAP, so WebAuthn needs a device node on the remote.
- **No USB/IP.** macOS has no native USB/IP server, and claiming a HID device
  away from macOS is not practical from user space. Relaying only the FIDO
  HID interface avoids both problems.
- **Raw passthrough.** The relay doesn't parse CTAP. Channel allocation, CBOR,
  PIN protocol and keepalives flow end to end between the remote browser and
  the real key, so any FIDO feature the key supports works.

## CTAPHID essentials

- Every report is 64 bytes. Bytes 0–3 are the channel id (CID). Byte 4 of an
  initialization packet is the command with the high bit set.
- A client sends `INIT` (0x86) on the broadcast CID `ffffffff` with an 8-byte
  nonce. The reply, also on broadcast, carries the nonce and the new CID.
- While waiting, the key sends `KEEPALIVE` (0xBB) on the client's CID, with
  status 1 (processing) or 2 (user presence needed). The local relay uses
  status 2 on remote-owned CIDs to post the "touch your key" notification.
  A CID counts as remote-owned once the remote has sent a command on it.

## macOS side

- python-fido2's `MacCtapHidConnection` opens the device with
  `IOHIDDeviceOpen(..., 0)`, which is shared, not exclusive. Chrome, ssh-agent
  and the relay can all hold it open at once. Input reports go to every
  opener, and each client ignores CIDs that aren't its own.
- `MacCtapHidConnection.read_packet()` schedules the device on a run loop
  only for the duration of one read, and reports that arrive between reads
  can be lost. The relay therefore schedules the device once, on a dedicated
  thread that runs the loop forever, and drains `read_queue` from another
  thread.
- `write_packet()` sends one 64-byte output report without a report ID
  prefix.

## Linux side (uhid)

- `struct uhid_event` is 4 + 4372 = 4376 bytes, because `uhid_create2_req` is
  the largest union member. Writes are padded to that size, and reads return
  one event.
- `UHID_CREATE2` (11): name[128], phys[64], uniq[64], rd_size u16, bus u16,
  vendor u32, product u32, version u32, country u32, rd_data[4096].
- `UHID_INPUT2` (12): size u16, then data. It sends 64 bytes, with no report
  ID because the descriptor declares none.
- `UHID_OUTPUT` (6): data[4096], then size u16 (at offset 4 + 4096), then
  rtype u8. Writers going through hidraw, like Chrome and libfido2, prefix
  report ID 0, so size is 65 and the first byte must be dropped.
- `UHID_GET_REPORT` (9) and `UHID_SET_REPORT` (13) must be answered (10/14,
  err=EIO). The kernel waits for a reply otherwise. CTAPHID never uses
  feature reports.
- The report descriptor is the standard FIDO one: usage page 0xF1D0, usage 1,
  one 64-byte input and one 64-byte output report. Reusing the real key's
  VID/PID lets udev's `fido_id` and browsers classify it as a security key.

## Permissions

- `/dev/uhid` is root-only, hence `sudo -n`. With no tty on the ssh channel,
  sudo can't ask for a password.
- udev creates the hidraw node as root 0600 and grants access through the
  `uaccess` tag, which applies only to the user of an active local seat
  session. An SSH-only server has no seat, so nobody gets access. The remote
  relay waits for `udevadm settle`, then chowns the node to `SUDO_UID`.
  Waiting matters: otherwise udev can reset the permissions after the chown.
- `uniq` includes the relay's pid, so the right node is found when several
  relays run at once.

## Scope and security model

- Only the FIDO HID interface is relayed. CCID (OpenPGP, PIV) and OTP are
  not. For GPG, use gpg-agent forwarding.
- While the relay runs, any process on the remote that can open the node
  (the user, and root) can send CTAP requests. Each one needs a physical
  touch, and user verification additionally needs the PIN typed in the
  browser. No key material ever leaves the key.
- Verified with Ubuntu 24.04 (kernel 6.8), Google Chrome 150 (.deb, headless
  and over X11), a YubiKey 5 on CTAP 2.0 firmware, python-fido2 2.2 and
  Homebrew OpenSSH 10.5 on macOS. Snap Chromium is untested. Its confinement
  gates hidraw through the `u2f-devices` interface, keyed on known vendor
  IDs.
