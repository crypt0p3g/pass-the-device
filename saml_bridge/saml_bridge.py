#!/usr/bin/env python3
"""SAML Bridge - a lab TLS-intercepting proxy for studying PRT-backed SSO.

SAML Bridge studies how a Microsoft Primary Refresh Token (PRT) cookie is
presented during a federated SSO handoff - the same handoff a VPN/SASE client's
embedded web view performs. It runs a local forward proxy that, for a small set
of explicitly permitted identity-provider hosts, terminates TLS with a
locally generated CA and injects an operator-supplied PRT cookie
(x-ms-RefreshTokenCredential) into the authorize request, merging it with the
cookies already present rather than discarding them.

Safety design (this is a MITM tool; treat it as one):
  * The CA is generated per install. No private key ships in this repository.
  * The CA carries X.509 NameConstraints limiting it to the permitted IdP
    domains, so even if the root is trusted it cannot vouch for other sites.
  * The proxy refuses to mint a leaf certificate for any non-permitted host and
    tunnels that traffic opaquely (no interception).
  * The PRT value is read from a file, stdin, or a hidden prompt - never from
    the command line - and is never written to disk or logged.
  * On exit the installed CA is removed and the system proxy is restored.

Authorized use only, in a lab or an engagement you are permitted to run.
"""

import argparse
import getpass
import os
import select
import socket
import ssl
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

DEFAULT_PERMITTED_DOMAINS = ("login.microsoftonline.com", "login.microsoft.com")
DEFAULT_PRT_COOKIE = "x-ms-RefreshTokenCredential"
# Paths on the IdP where the authorize/login exchange happens.
DEFAULT_PATH_MARKERS = ("saml2", "/oauth2/authorize", "/oauth2/v2.0/authorize", "/login", "/kmsi")

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 8888
MAX_HEAD_BYTES = 256 * 1024
RELAY_IDLE_SECONDS = 60


# --------------------------------------------------------------------------- #
# Certificate authority
# --------------------------------------------------------------------------- #
def generate_ca(permitted_domains, out_cert: Path, out_key: Path):
    """Create a name-constrained CA. Overwrites nothing silently."""
    for path in (out_cert, out_key):
        if path.exists():
            raise FileExistsError(f"{path} already exists; remove it first")

    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "SAML Bridge Lab CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SAML Bridge (lab only)"),
    ])
    now = datetime.now(timezone.utc)
    permitted = [x509.DNSName(domain) for domain in permitted_domains]
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.NameConstraints(permitted_subtrees=permitted, excluded_subtrees=None),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    cert = builder.sign(private_key=key, algorithm=hashes.SHA256())

    # O_EXCL + 0600 from the start: the key is never briefly world-readable.
    fd = os.open(out_key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    out_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert, key


class LeafFactory:
    """Mints per-host leaf certs signed by the CA, only for permitted hosts."""

    def __init__(self, ca_cert, ca_key, permitted_domains):
        self.ca_cert = ca_cert
        self.ca_key = ca_key
        self.permitted = tuple(permitted_domains)
        self._cache = {}
        self._lock = threading.Lock()

    def permits(self, host: str) -> bool:
        host = host.lower()
        return any(host == d or host.endswith("." + d) for d in self.permitted)

    def cert_for(self, host: str):
        if not self.permits(host):
            raise PermissionError(f"host not permitted for interception: {host}")
        with self._lock:
            if host in self._cache:
                return self._cache[host]
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            now = datetime.now(timezone.utc)
            cert = (
                x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
                .issuer_name(self.ca_cert.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=5))
                .not_valid_after(now + timedelta(days=2))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(
                    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                    critical=False,
                )
                # Strict validators (e.g. Python 3.13+ defaults) reject a leaf
                # without key identifiers.
                .add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                    critical=False,
                )
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
                    critical=False,
                )
                .sign(private_key=self.ca_key, algorithm=hashes.SHA256())
            )
            pair = _materialize_context(cert, key)
            self._cache[host] = pair
            return pair


def _materialize_context(cert, key):
    """Build a server SSLContext from an in-memory cert/key via temp files."""
    import tempfile

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as handle:
        handle.write(cert_pem + key_pem)
        temp_path = handle.name
    try:
        os.chmod(temp_path, 0o600)
    except OSError:
        pass
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=temp_path)
    try:
        os.unlink(temp_path)
    except OSError:
        pass
    return ctx


# --------------------------------------------------------------------------- #
# Cookie handling
# --------------------------------------------------------------------------- #
def merge_cookie_header(existing_value: str, cookie_name: str, cookie_value: str) -> str:
    """Set cookie_name to cookie_value, preserving every other cookie."""
    pairs = []
    replaced = False
    if existing_value:
        for chunk in existing_value.split(";"):
            chunk = chunk.strip()
            if not chunk:
                continue
            name = chunk.split("=", 1)[0].strip()
            if name.lower() == cookie_name.lower():
                pairs.append(f"{cookie_name}={cookie_value}")
                replaced = True
            else:
                pairs.append(chunk)
    if not replaced:
        pairs.append(f"{cookie_name}={cookie_value}")
    return "; ".join(pairs)


def path_matches(path: bytes, markers) -> bool:
    lowered = path.lower()
    return any(marker.encode().lower() in lowered for marker in markers)


# --------------------------------------------------------------------------- #
# PRT input (never from argv)
# --------------------------------------------------------------------------- #
def read_prt(args) -> str:
    if args.prt_file:
        value = Path(args.prt_file).read_text(encoding="utf-8").strip()
        if not value:
            raise ValueError("--prt-file is empty")
        return value
    if args.prt_stdin:
        value = sys.stdin.readline().strip()
        if not value:
            raise ValueError("no PRT value on stdin")
        return value
    value = getpass.getpass("PRT cookie value (hidden): ").strip()
    if not value:
        raise ValueError("no PRT value entered")
    return value


# --------------------------------------------------------------------------- #
# HTTP framing (minimal, request-head only)
# --------------------------------------------------------------------------- #
class Reader:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def read_head(self):
        while b"\r\n\r\n" not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                break
            self.buf += chunk
            if len(self.buf) > MAX_HEAD_BYTES:
                break
        head, _, rest = self.buf.partition(b"\r\n\r\n")
        self.buf = rest
        return head

    def leftover(self):
        data, self.buf = self.buf, b""
        return data


def parse_head(head: bytes):
    lines = head.split(b"\r\n")
    start = lines[0] if lines else b""
    headers = []
    for line in lines[1:]:
        if b":" in line:
            key, _, value = line.partition(b":")
            headers.append((key.strip(), value.strip()))
    return start, headers


def build_head(start, headers):
    out = [start]
    for key, value in headers:
        out.append(key + b": " + value)
    return b"\r\n".join(out) + b"\r\n\r\n"


class RequestRewriter:
    """Incremental HTTP/1.1 request-stream rewriter.

    Feed it the decrypted client bytes as they arrive; it returns the bytes to
    send upstream. Every request head on the connection is offered to
    ``rewrite_head(start_line, headers) -> headers``; request bodies are passed
    through untouched, tracked by Content-Length so the next head is found on a
    kept-alive connection. If the framing cannot be followed (chunked request
    body, protocol upgrade, oversized head) the rest of the connection is
    relayed verbatim.
    """

    def __init__(self, rewrite_head):
        self.rewrite_head = rewrite_head
        self.buf = b""
        self.body_left = 0
        self.passthrough = False

    def feed(self, data: bytes) -> bytes:
        out = []
        self.buf += data
        while self.buf:
            if self.passthrough:
                out.append(self.buf)
                self.buf = b""
                break
            if self.body_left:
                chunk, self.buf = self.buf[: self.body_left], self.buf[self.body_left :]
                self.body_left -= len(chunk)
                out.append(chunk)
                continue
            end = self.buf.find(b"\r\n\r\n")
            if end < 0:
                if len(self.buf) > MAX_HEAD_BYTES:
                    self.passthrough = True
                    continue
                break
            head, self.buf = self.buf[:end], self.buf[end + 4 :]
            start, headers = parse_head(head)
            for key, value in headers:
                name = key.lower()
                if name == b"content-length":
                    try:
                        self.body_left = int(value)
                    except ValueError:
                        self.passthrough = True
                elif name in (b"transfer-encoding", b"upgrade"):
                    self.passthrough = True
            out.append(build_head(start, self.rewrite_head(start, headers)))
        return b"".join(out)


# --------------------------------------------------------------------------- #
# Proxy
# --------------------------------------------------------------------------- #
class BridgeProxy:
    def __init__(self, factory: LeafFactory, prt_value, cookie_name, path_markers,
                 listen=(LISTEN_HOST, LISTEN_PORT), verbose=False):
        self.factory = factory
        self.prt_value = prt_value
        self.cookie_name = cookie_name
        self.path_markers = path_markers
        self.listen = listen
        self.verbose = verbose
        self.injections = 0

    def log(self, message):
        if self.verbose:
            print(f"[.] {message}", file=sys.stderr)

    def serve_forever(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(self.listen)
        srv.listen(128)
        print(f"[+] SAML Bridge listening on {self.listen[0]}:{self.listen[1]}")
        print(f"[+] Intercepting (name-constrained): {', '.join(self.factory.permitted)}")
        print(f"[+] Injecting '{self.cookie_name}' on paths containing: {', '.join(self.path_markers)}")
        try:
            while True:
                conn, _ = srv.accept()
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
        except KeyboardInterrupt:
            print("\n[*] shutting down")
        finally:
            srv.close()

    def _handle(self, conn):
        try:
            reader = Reader(conn)
            head = reader.read_head()
            if not head:
                conn.close()
                return
            start, _ = parse_head(head)
            parts = start.split(b" ")
            if parts and parts[0].upper() == b"CONNECT":
                self._handle_connect(conn, reader, parts[1].decode("latin1"))
            else:
                conn.close()
        except Exception as exc:  # pragma: no cover - defensive
            self.log(f"handler error: {exc}")
            try:
                conn.close()
            except OSError:
                pass

    def _handle_connect(self, conn, reader, authority):
        host, _, port_text = authority.rpartition(":")
        if not host:  # no port given
            host, port_text = authority, "443"
        host = host.strip("[]")  # IPv6 literal
        port = int(port_text)
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        if not self.factory.permits(host):
            # Not a permitted IdP host: tunnel opaquely, no interception.
            self._tunnel(conn, reader, host, port)
            return

        ctx = self.factory.cert_for(host)
        try:
            client_tls = ctx.wrap_socket(conn, server_side=True)
        except ssl.SSLError as exc:
            self.log(f"client TLS handshake failed for {host}: {exc}")
            conn.close()
            return
        self._intercept(client_tls, host, port)

    def _tunnel(self, conn, reader, host, port):
        try:
            upstream = socket.create_connection((host, port), timeout=30)
        except OSError:
            conn.close()
            return
        try:
            leftover = reader.leftover()
            if leftover:
                upstream.sendall(leftover)
            _relay(conn, upstream)
        except OSError as exc:
            self.log(f"tunnel error for {host}: {exc}")
        finally:
            for sock in (conn, upstream):
                try:
                    sock.close()
                except OSError:
                    pass

    def _intercept(self, client_tls, host, port):
        upstream_ctx = ssl.create_default_context()
        try:
            raw = socket.create_connection((host, port), timeout=30)
            upstream = upstream_ctx.wrap_socket(raw, server_hostname=host)
        except (OSError, ssl.SSLError) as exc:
            self.log(f"upstream TLS failed for {host}: {exc}")
            client_tls.close()
            return
        # Responses are relayed verbatim. Requests go through the rewriter so
        # that every request on a kept-alive connection is inspected, not just
        # the first one (browsers reuse the connection for the authorize call).
        rewriter = RequestRewriter(self._rewrite_head)
        socks = [client_tls, upstream]
        try:
            while True:
                readable, _, errored = select.select(socks, [], socks, RELAY_IDLE_SECONDS)
                if errored or not readable:
                    break
                closed = False
                for sock in readable:
                    data = sock.recv(65536)
                    if not data:
                        closed = True
                        break
                    if sock is client_tls:
                        data = rewriter.feed(data)
                        if data:
                            upstream.sendall(data)
                    else:
                        client_tls.sendall(data)
                if closed:
                    break
        except (OSError, ssl.SSLError) as exc:
            self.log(f"intercept error for {host}: {exc}")
        finally:
            for sock in (client_tls, upstream):
                try:
                    sock.close()
                except OSError:
                    pass

    def _rewrite_head(self, start, headers):
        parts = start.split(b" ")
        path = parts[1] if len(parts) >= 2 else b""
        if path_matches(path, self.path_markers):
            return self._inject(headers)
        return headers

    def _inject(self, headers):
        new = []
        found = False
        for key, value in headers:
            if key.lower() == b"cookie":
                merged = merge_cookie_header(
                    value.decode("latin1"), self.cookie_name, self.prt_value
                )
                new.append((key, merged.encode("latin1")))
                found = True
            else:
                new.append((key, value))
        if not found:
            new.append((b"Cookie", f"{self.cookie_name}={self.prt_value}".encode("latin1")))
        self.injections += 1
        self.log(f"injected {self.cookie_name} (merged with existing cookies)")
        return new


def _relay(left, right):
    socks = [left, right]
    while True:
        readable, _, errored = select.select(socks, [], socks, RELAY_IDLE_SECONDS)
        if errored or not readable:
            break
        for sock in readable:
            try:
                data = sock.recv(65536)
            except OSError:
                return
            if not data:
                return
            target = right if sock is left else left
            try:
                target.sendall(data)
            except OSError:
                return


# --------------------------------------------------------------------------- #
# System integration (Windows proxy + CurrentUser root store)
# --------------------------------------------------------------------------- #
def install_ca_windows(cert_path: Path):
    if sys.platform != "win32":
        return False
    import subprocess

    subprocess.run(
        ["certutil", "-user", "-addstore", "Root", str(cert_path)],
        check=True, capture_output=True,
    )
    return True


def remove_ca_windows(cert_path: Path):
    if sys.platform != "win32":
        return False
    import subprocess

    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    thumbprint = cert.fingerprint(hashes.SHA1()).hex()
    subprocess.run(
        ["certutil", "-user", "-delstore", "Root", thumbprint],
        check=False, capture_output=True,
    )
    return True


def set_windows_proxy(host, port):
    if sys.platform != "win32":
        return None
    import winreg

    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        0, winreg.KEY_ALL_ACCESS,
    )
    previous = {}
    for name in ("ProxyEnable", "ProxyServer"):
        try:
            previous[name] = winreg.QueryValueEx(key, name)
        except FileNotFoundError:
            previous[name] = None
    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"{host}:{port}")
    winreg.CloseKey(key)
    _notify_wininet()
    return previous


def restore_windows_proxy(previous):
    if sys.platform != "win32" or previous is None:
        return
    import winreg

    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        0, winreg.KEY_ALL_ACCESS,
    )
    for name, value in previous.items():
        if value is None:
            try:
                winreg.DeleteValue(key, name)
            except FileNotFoundError:
                pass
        else:
            winreg.SetValueEx(key, name, 0, value[1], value[0])
    winreg.CloseKey(key)
    _notify_wininet()


def _notify_wininet():  # pragma: no cover - Windows only
    import ctypes

    internet = ctypes.windll.Wininet
    internet.InternetSetOptionW(0, 39, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
    internet.InternetSetOptionW(0, 37, 0, 0)  # INTERNET_OPTION_REFRESH


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _load_ca(cert_path: Path, key_path: Path):
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    key = load_pem_private_key(key_path.read_bytes(), password=None)
    return cert, key


def cmd_gen_ca(args):
    domains = args.domain or list(DEFAULT_PERMITTED_DOMAINS)
    generate_ca(domains, Path(args.ca_cert), Path(args.ca_key))
    print(f"[+] Generated name-constrained CA for: {', '.join(domains)}")
    print(f"    cert: {args.ca_cert}")
    print(f"    key:  {args.ca_key}  (keep private; never commit)")
    if sys.platform != "win32":
        print("[!] On non-Windows, install the cert into your test browser/profile trust store")
        print("    manually, and remove it when finished.")
    return 0


def cmd_start(args):
    cert_path, key_path = Path(args.ca_cert), Path(args.ca_key)
    if not cert_path.exists() or not key_path.exists():
        raise SystemExit("[-] CA not found; run 'gen-ca' first")
    ca_cert, ca_key = _load_ca(cert_path, key_path)

    domains = args.domain or _domains_from_ca(ca_cert) or list(DEFAULT_PERMITTED_DOMAINS)
    factory = LeafFactory(ca_cert, ca_key, domains)
    prt = read_prt(args)
    markers = args.path_marker or list(DEFAULT_PATH_MARKERS)

    if args.listen_host not in ("127.0.0.1", "::1", "localhost"):
        print(
            f"[!] Listening on {args.listen_host}: anyone who can reach this port and "
            "trusts the CA gets the PRT cookie injected. Keep it on loopback.",
            file=sys.stderr,
        )

    proxy = BridgeProxy(
        factory, prt, args.cookie_name, markers,
        listen=(args.listen_host, args.listen_port), verbose=args.verbose,
    )

    previous_proxy = None
    ca_installed = False
    try:
        if args.install:
            if sys.platform == "win32":
                install_ca_windows(cert_path)
                ca_installed = True
                previous_proxy = set_windows_proxy(args.listen_host, args.listen_port)
                print("[+] CA installed to CurrentUser Root; system proxy set")
            else:
                print("[!] --install is Windows-only; running proxy without installing CA")
        proxy.serve_forever()
    finally:
        if previous_proxy is not None:
            restore_windows_proxy(previous_proxy)
            print("[*] system proxy restored")
        if ca_installed:
            remove_ca_windows(cert_path)
            print("[*] CA removed from CurrentUser Root")
    return 0


def _domains_from_ca(ca_cert):
    try:
        nc = ca_cert.extensions.get_extension_for_class(x509.NameConstraints).value
        return [d.value for d in (nc.permitted_subtrees or []) if isinstance(d, x509.DNSName)]
    except x509.ExtensionNotFound:
        return []


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("gen-ca", help="generate a name-constrained lab CA")
    gen.add_argument("--ca-cert", default="bridge-ca.crt")
    gen.add_argument("--ca-key", default="bridge-ca.key")
    gen.add_argument("--domain", action="append", help="permitted IdP domain (repeatable)")

    start = sub.add_parser("start", help="run the intercepting proxy")
    start.add_argument("--ca-cert", default="bridge-ca.crt")
    start.add_argument("--ca-key", default="bridge-ca.key")
    start.add_argument("--domain", action="append", help="override permitted domains")
    start.add_argument("--listen-host", default=LISTEN_HOST)
    start.add_argument("--listen-port", type=int, default=LISTEN_PORT)
    start.add_argument("--cookie-name", default=DEFAULT_PRT_COOKIE)
    start.add_argument("--path-marker", action="append",
                       help="path substring that triggers injection (repeatable)")
    prt_group = start.add_mutually_exclusive_group()
    prt_group.add_argument("--prt-file", help="read PRT value from this file")
    prt_group.add_argument("--prt-stdin", action="store_true", help="read PRT value from stdin")
    start.add_argument("--install", action="store_true",
                       help="(Windows) install CA to CurrentUser Root and set system proxy, then clean up on exit")
    start.add_argument("--verbose", action="store_true")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.command == "gen-ca":
        return cmd_gen_ca(args)
    if args.command == "start":
        return cmd_start(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
