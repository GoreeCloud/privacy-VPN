"""Positive trusted-chain and negative hostname tests for WSS on localhost.

Private CA is trusted for this child process only via SSL_CERT_FILE;
the host trust store and system resolver are never modified.
"""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import threading
import time

from check_wss_tls import BINARY, free_port, udp_echo, probe, start, stop
from privacyvpn.obfs import render_client


def openssl(*args):
    subprocess.run(["openssl", *map(str, args)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def test():
    with tempfile.TemporaryDirectory(prefix="gcvpn-private-ca-") as tmp:
        root = Path(tmp)
        ca_key, ca_cert = root / "ca.key", root / "ca.pem"
        srv_key, srv_csr = root / "server.key", root / "server.csr"
        srv_cert = root / "server.pem"
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=GoreeCloud-Test-CA",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout", ca_key, "-out", ca_cert)
        openssl("req", "-newkey", "rsa:2048", "-nodes",
                "-subj", "/CN=localhost",
                "-keyout", srv_key, "-out", srv_csr)
        # Real signed leaf needs SAN and serverAuth EKU.
        leaf = root / "server.ext"
        leaf.write_text("subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n"
                        "keyUsage=digitalSignature,keyEncipherment\n")
        openssl("x509", "-req", "-in", srv_csr, "-CA", ca_cert,
                "-CAkey", ca_key, "-CAcreateserial", "-days", "1",
                "-extfile", leaf, "-out", srv_cert)
        ca_key.chmod(0o600)
        srv_key.chmod(0o600)
        port, echo = free_port(__import__("socket").SOCK_STREAM), free_port(__import__("socket").SOCK_DGRAM)
        stopped = threading.Event()
        target = threading.Thread(target=udp_echo, args=(echo, stopped), daemon=True)
        target.start()
        server = start([BINARY, "server", "--restrict-to", f"127.0.0.1:{echo}",
                        "--tls-certificate", str(srv_cert),
                        "--tls-private-key", str(srv_key),
                        f"wss://127.0.0.1:{port}"])
        try:
            time.sleep(0.8)
            assert server.poll() is None, "WSS server failed"
            template = render_client({"entry": {"endpoint": "127.0.0.1", "listen_port": 51820},
                                      "transport": {"hostname": "localhost", "tls_port": port}})
            argv = shlex.split(template.splitlines()[-1])
            assert "--tls-verify-certificate" in argv
            for hostname, expect_pass in (("localhost", True), ("127.0.0.1", False)):
                local = free_port(__import__("socket").SOCK_DGRAM)
                cmd = [BINARY] + argv[2:]
                cmd[cmd.index("-L") + 1] = (
                    f"udp://127.0.0.1:{local}:127.0.0.1:{echo}?timeout_sec=0")
                cmd[-1] = f"wss://{hostname}:{port}"
                env = dict(os.environ, SSL_CERT_FILE=str(ca_cert))
                with tempfile.TemporaryFile() as err:
                    client = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                              stderr=err, env=env)
                    try:
                        time.sleep(0.5)
                        result = probe(local, b"trusted-chain-test")
                        err.seek(0)
                        detail = err.read().decode(errors="replace")[-1200:]
                        print(hostname, "forwarded" if result else "blocked",
                              "expected", expect_pass)
                        if result != expect_pass:
                            raise AssertionError(f"wstunnel TLS outcome for {hostname}: {detail}")
                    finally:
                        stop(client)
        finally:
            stop(server)
            stopped.set()
            target.join(timeout=2)


if __name__ == "__main__":
    test()
