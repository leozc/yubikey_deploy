#!/usr/bin/env python3
"""Remote half of the FIDO relay: a virtual FIDO HID device on this Linux host,
backed by a real security key on another machine (fido-relay-local.py starts
this over ssh).

stdin carries raw 64-byte CTAPHID input reports (key -> host); stdout carries
64-byte output reports (host -> key). Needs root for /dev/uhid. The hidraw
node it creates is handed to $SUDO_UID, because without a local seat session
udev's uaccess rule grants nobody access. The device disappears when stdin
closes. Standard library only.

Usage: sudo fido-uhid-relay.py <vid-hex> <pid-hex>
"""
import glob
import os
import select
import struct
import subprocess
import sys
import time

# linux/uhid.h
UHID_DESTROY = 1
UHID_OUTPUT = 6
UHID_GET_REPORT = 9
UHID_GET_REPORT_REPLY = 10
UHID_CREATE2 = 11
UHID_INPUT2 = 12
UHID_SET_REPORT = 13
UHID_SET_REPORT_REPLY = 14
UHID_DATA_MAX = 4096
EV_SIZE = 4 + 4372  # sizeof(struct uhid_event); uhid_create2_req is the largest member
BUS_USB = 0x03
EIO = 5

PKT = 64
NAME = b"FIDO relay (ssh)"
UNIQ = f"fido-relay-{os.getpid()}".encode()

# Standard CTAPHID report descriptor: one 64-byte input and one output report.
RDESC = bytes.fromhex(
    "06d0f1 0901 a101"
    " 0920 1500 26ff00 7508 9540 8102"
    " 0921 1500 26ff00 7508 9540 9102"
    " c0"
)


def event(kind, payload=b""):
    return (struct.pack("<I", kind) + payload).ljust(EV_SIZE, b"\0")


def hand_over_hidraw():
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid is None:
        return
    deadline = time.time() + 5
    while time.time() < deadline:
        for uevent in glob.glob("/sys/class/hidraw/hidraw*/device/uevent"):
            with open(uevent) as f:
                if f"HID_UNIQ={UNIQ.decode()}\n" in f.read():
                    # Let udev apply its default permissions first, then ours.
                    subprocess.run(["udevadm", "settle", "-t", "5"], check=False)
                    node = "/dev/" + uevent.split("/")[4]
                    os.chown(node, int(uid), int(gid))
                    os.chmod(node, 0o600)
                    print(f"fido-uhid-relay: {node}", file=sys.stderr, flush=True)
                    return
        time.sleep(0.1)
    print("fido-uhid-relay: hidraw node did not appear", file=sys.stderr)


def main():
    vid, pid = int(sys.argv[1], 16), int(sys.argv[2], 16)
    fd = os.open("/dev/uhid", os.O_RDWR)
    create = struct.pack(
        "<128s64s64sHHIIII", NAME, b"fido-relay", UNIQ,
        len(RDESC), BUS_USB, vid, pid, 0, 0,
    ) + RDESC
    os.write(fd, event(UHID_CREATE2, create))
    hand_over_hidraw()

    stdin, stdout = sys.stdin.fileno(), sys.stdout.fileno()
    pending = b""
    try:
        while True:
            ready, _, _ = select.select([fd, stdin], [], [])
            if stdin in ready:
                chunk = os.read(stdin, 4096)
                if not chunk:
                    break
                pending += chunk
                while len(pending) >= PKT:
                    pkt, pending = pending[:PKT], pending[PKT:]
                    os.write(fd, event(UHID_INPUT2, struct.pack("<H", PKT) + pkt))
            if fd in ready:
                ev = os.read(fd, EV_SIZE)
                kind = struct.unpack_from("<I", ev)[0]
                if kind == UHID_OUTPUT:
                    size = struct.unpack_from("<H", ev, 4 + UHID_DATA_MAX)[0]
                    data = ev[4:4 + size]
                    if size == PKT + 1:  # hidraw writers prefix report ID 0
                        data = data[1:]
                    os.write(stdout, data[:PKT].ljust(PKT, b"\0"))
                elif kind == UHID_GET_REPORT:  # CTAPHID has no feature reports
                    req = struct.unpack_from("<I", ev, 4)[0]
                    os.write(fd, event(UHID_GET_REPORT_REPLY, struct.pack("<IHH", req, EIO, 0)))
                elif kind == UHID_SET_REPORT:
                    req = struct.unpack_from("<I", ev, 4)[0]
                    os.write(fd, event(UHID_SET_REPORT_REPLY, struct.pack("<IH", req, EIO)))
    finally:
        os.write(fd, event(UHID_DESTROY))
        os.close(fd)


if __name__ == "__main__":
    main()
