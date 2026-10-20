"""Minimal RFC 1035 A-query fixture for the isolated three-node VPN lab.

Real DNS wire-format packets; not a system resolver, public DNS, or DoH/DoT.
"""
import socket
import struct
import sys

TXID = 0x6A31
NAME = "vpn-test.example"
ANSWER_IP = "192.0.2.123"


def question():
    labels = NAME.split(".")
    qname = b"".join(bytes([len(part)]) + part.encode("ascii")
                     for part in labels) + b"\x00"
    return qname + struct.pack("!HH", 1, 1)


def query():
    return struct.pack("!HHHHHH", TXID, 0x0100, 1, 0, 0, 0) + question()


def assert_query(data):
    assert data == query(), f"Unexpected DNS wire question: {data.hex()[:100]}"


def reply(request):
    assert_query(request)
    header = struct.pack("!HHHHHH", TXID, 0x8180, 1, 1, 0, 0)
    # The answer name is a compression pointer to question offset 12.
    record = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4)
    return header + question() + record + socket.inet_aton(ANSWER_IP)


def assert_reply(data):
    assert data == reply(query()), f"Unexpected DNS wire answer: {data.hex()[:100]}"


def client(destination, port, *, require_reply):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.8)
        attempts = 30 if require_reply else 1
        for _ in range(attempts):
            sock.sendto(query(), (destination, port))
            if not require_reply:
                print("dns-query-sent")
                return
            try:
                received, _ = sock.recvfrom(2048)
                assert_reply(received)
                print("dns-answer-valid")
                return
            except socket.timeout:
                pass
    raise RuntimeError("No valid DNS reply within recovery window")


def main():
    if len(sys.argv) != 4:
        raise SystemExit("Usage: dns_wire.py DEST_IPV4 PORT expect|send")
    destination, port, mode = sys.argv[1:]
    if mode not in ("expect", "send"):
        raise SystemExit("mode must be expect or send")
    client(destination, int(port), require_reply=mode == "expect")


if __name__ == "__main__":
    main()
