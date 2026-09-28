#!/usr/bin/env python3
"""Expose a FIDO security key plugged into this Mac as a FIDO HID device on a
remote Linux host, so browsers there (including headless Chrome) can use it
for WebAuthn/U2F.

Raw 64-byte CTAPHID reports are relayed over ssh to fido-uhid-relay.py on the
remote, which creates a virtual HID device through /dev/uhid. The key is
opened non-exclusively, so this Mac keeps using it too. Every operation still
needs a touch here; a notification says when the remote is waiting for one.

macOS only. Needs python-fido2 (pip install fido2).

Usage: fido-relay-local.py HOST [--remote-cmd CMD] [--vid HEX] [--no-notify]
Ctrl-C (or the ssh session ending) removes the device from the remote.
"""
import argparse
import subprocess
import sys
import threading
import time

from fido2.hid.macos import (
    K_CF_RUNLOOP_DEFAULT_MODE,
    MacCtapHidConnection,
    cf,
    iokit,
    list_descriptors,
)

PKT = 64
BROADCAST_CID = b"\xff\xff\xff\xff"
CTAPHID_KEEPALIVE = 0xBB
STATUS_UPNEEDED = 2


def parse_args():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("host", help="ssh destination (as in ~/.ssh/config)")
    ap.add_argument(
        "--remote-cmd",
        default="sudo -n /usr/local/bin/fido-uhid-relay.py",
        help="command that starts the remote half (default: %(default)s)",
    )
    ap.add_argument(
        "--vid",
        type=lambda s: int(s, 16),
        help="only relay a key with this USB vendor id in hex (1050 = Yubico)",
    )
    ap.add_argument("--no-notify", action="store_true", help="no touch notifications")
    return ap.parse_args()


def main():
    args = parse_args()
    descs = [d for d in list_descriptors() if args.vid is None or d.vid == args.vid]
    if not descs:
        sys.exit("no FIDO HID device found")
    desc = descs[0]
    conn = MacCtapHidConnection(desc)

    # Only the relay stream travels over this session: no agent, X11 or
    # RemoteForward from ssh_config, so it can't steal the gpg socket.
    proc = subprocess.Popen(
        ["ssh", "-T", "-x", "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
         "-o", "ServerAliveInterval=15", args.host,
         f"{args.remote_cmd} {desc.vid:04x} {desc.pid:04x}"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )

    remote_cids = set()  # CTAPHID channels the remote side sends commands on
    last_notice = [0.0]

    def notify_touch():
        # A remote (possibly headless) browser shows nothing here, so say when
        # to touch; the key only waits about 30 seconds.
        if args.no_notify or time.time() - last_notice[0] < 10:
            return
        last_notice[0] = time.time()
        subprocess.Popen([
            "/usr/bin/osascript",
            "-e", "on run argv",
            "-e", "display notification (item 1 of argv) with title (item 2 of argv)",
            "-e", "end run",
            "Touch your security key", f"{args.host} is waiting",
        ])

    def run_loop():
        # fido2's read_packet() schedules the device on a run loop only while
        # a read is pending; a relay must receive every input report, so keep
        # it scheduled for the life of the process.
        iokit.IOHIDDeviceScheduleWithRunLoop(
            conn.handle, cf.CFRunLoopGetCurrent(), K_CF_RUNLOOP_DEFAULT_MODE
        )
        while True:
            cf.CFRunLoopRunInMode(K_CF_RUNLOOP_DEFAULT_MODE, 1.0, False)

    def device_to_remote():
        while True:
            pkt = conn.read_queue.get()
            if pkt[4] == CTAPHID_KEEPALIVE and pkt[7] == STATUS_UPNEEDED and pkt[:4] in remote_cids:
                notify_touch()
            proc.stdin.write(pkt[:PKT].ljust(PKT, b"\0"))
            proc.stdin.flush()

    threading.Thread(target=run_loop, daemon=True).start()
    threading.Thread(target=device_to_remote, daemon=True).start()
    print(f"relaying {desc.product_name} ({desc.vid:04x}:{desc.pid:04x}) to {args.host}", flush=True)

    while len(pkt := proc.stdout.read(PKT)) == PKT:
        if pkt[:4] != BROADCAST_CID:
            remote_cids.add(pkt[:4])
        conn.write_packet(pkt)
    sys.exit(proc.wait())


if __name__ == "__main__":
    main()
