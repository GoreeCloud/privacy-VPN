"""Exercise upstream wstunnel WSS certificate verification on loopback only.

Requires openssl and verified upstream wstunnel via GCVPN_WSTUNNEL.
No global CA, resolver, firewall, route, or production configuration is touched.
"""
import os
from pathlib import Path
import shlex
import socket
import subprocess
import tempfile
import threading
import time
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from privacyvpn.obfs import render_client

BINARY = os.environ.get("GCVPN_WSTUNNEL")
if not BINARY or not Path(BINARY).is_file():
    raise SystemExit("Set GCVPN_WSTUNNEL to a verified temporary upstream binary")


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def udp_echo(port, stop):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", port))
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                payload, addr = sock.recvfrom(2048)
                sock.sendto(payload, addr)
            except socket.timeout:
                pass


def probe(port, expected):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.9)
        for _ in range(4):
            sock.sendto(expected, ("127.0.0.1", port))
            try:
                reply, _ = sock.recvfrom(1024)
                return reply == expected
            except socket.timeout:
                continue
    return False


def start(argv):
    return subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def stop(proc):
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def main():
    with tempfile.TemporaryDirectory(prefix="gcvpn-loopback-tls-") as tmp:
        root = Path(tmp)
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-nodes", "-days", "1", "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost",
            "-keyout", str(key), "-out", str(cert)
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        key.chmod(0o600)
        ssl_port = free_port(socket.SOCK_STREAM)
        echo_port = free_port(socket.SOCK_DGRAM)
        stop_echo = threading.Event()
        echo_thread = threading.Thread(
            target=udp_echo, args=(echo_port, stop_echo), daemon=True)
        echo_thread.start()
        server = start([
            BINARY, "server", "--restrict-to", f"127.0.0.1:{echo_port}",
            "--tls-certificate", str(cert), "--tls-private-key", str(key),
            f"wss://127.0.0.1:{ssl_port}"
        ])
        try:
            time.sleep(0.8)
            if server.poll() is not None:
                raise AssertionError("WSS loopback server could not start")

            template = render_client({
                "entry": {"endpoint": "127.0.0.1", "listen_port": 51820},
                "transport": {"hostname": "localhost", "tls_port": ssl_port}
            })
            argv = shlex.split(template.strip().splitlines()[-1])
            assert argv[:3] == ["exec", "wstunnel", "client"], argv[:3]
            assert "--tls-verify-certificate" in argv
            for verify in (True, False):
                local_port = free_port(socket.SOCK_DGRAM)
                # Exercise the exact generated client arguments, rewriting
                # only loopback ports and server URI for this self-contained lab.
                args = [BINARY] + argv[2:]
                args[args.index("-L") + 1] = (
                    f"udp://127.0.0.1:{local_port}:"
                    f"127.0.0.1:{echo_port}?timeout_sec=0"
                )
                args[-1] = f"wss://127.0.0.1:{ssl_port}"
                if not verify:
                    # Intentional test-only negative control, never emitted
                    # by the production GoreeCloud profile renderer.
                    args.remove("--tls-verify-certificate")
                proc = start(args)
                try:
                    time.sleep(0.55)
                    forwarded = probe(local_port, b"loopback-wss-test")
                    if verify and forwarded:
                        raise AssertionError("Untrusted WSS peer was accepted")
                    if not verify and not forwarded:
                        raise AssertionError("Test control did not forward UDP")
                    print("PASS", "untrusted certificate rejected" if verify
                          else "control: UDP echo through test-only unverified WSS")
                finally:
                    stop(proc)
        finally:
            stop(server)
            stop_echo.set()
            echo_thread.join(timeout=2)


if __name__ == "__main__":
    main()
