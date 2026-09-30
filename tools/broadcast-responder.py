#!/usr/bin/env python3
"""Answers Open Moxdash's LAN broadcast probe.

Listens on UDP 55399. When a datagram arrives whose payload is exactly the probe
string, it unicasts an ACK (a prefix plus this machine's hostname) back to the sender.
Open Moxdash treats that ACK as proof that its broadcast was received by another
process and answered.

Run it on a machine other than the one running Open Moxdash, ideally a separate
physical device. If it shares a hypervisor with Open Moxdash, the probe only crosses
the host's virtual bridge and never tests the physical network.

The port and both strings must match checks/network.js.
"""
import platform
import socket

PORT = 55399
PROBE_PAYLOAD = b"open-moxdash-broadcast-probe"
ACK_PREFIX = b"open-moxdash-broadcast-ack:"


def main():
    hostname = platform.node().encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", PORT))
    while True:
        data, addr = sock.recvfrom(1024)
        if data == PROBE_PAYLOAD:
            sock.sendto(ACK_PREFIX + hostname, addr)


if __name__ == "__main__":
    main()
