#!/usr/bin/env python3
"""VPN gateway fingerprinter.

Given a VPN hostname, say which remote-access product answers, how it
authenticates, which identity provider it delegates to, and what it exposes
before login. Three products are recognised:

  - Palo Alto GlobalProtect   (portal and gateway prelogin.esp)
  - Cisco ASA / Secure Client (AnyConnect XML handshake, /+CSCOE+/logon.html,
                               /CACHE/sdesktop/data.xml)
  - Fortinet FortiGate SSL VPN (/remote/login, /remote/info, /remote/saml/start)

Every product is reported with its endpoint, authentication method (SAML,
password, certificate required, or unknown), the SAML destination, and what it
exposes before login. Identity providers and notes are listed separately.

For any server, recognised or not, it also reads the TLS client-certificate
request: whether the server asks for a certificate in the handshake, whether
it insists on one, and which certificate authorities it says it accepts
(see client_cert_probe.py).

Optionally (--zscaler DOMAIN --zscaler-cloud CLOUD) it also asks one Zscaler
cloud whether a company domain is registered there and which identity provider
its sign-in is sent to.

All probes are unauthenticated: they send what a stock client sends before the
user types anything. No credentials are sent. Use only against hosts you own
or are explicitly permitted to assess.
"""

import argparse
import base64
import hashlib
import json
import re
import socket
import ssl
import sys
import zlib
from html import unescape
from urllib.parse import parse_qs, urljoin, urlparse

import requests
from requests.exceptions import RequestException

import client_cert_probe

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
ANYCONNECT_VERSION = "4.10.07061"
ANYCONNECT_UA = f"AnyConnect Windows {ANYCONNECT_VERSION}"
ZSCALER_UA = "Windows Microsoft Windows 11 Pro ZTunnel/4.3.0.121"
# Shown in --help as a reminder; any other cloud name is accepted too.
ZSCALER_CLOUDS = (
    "zscaler.net", "zscalerone.net", "zscalertwo.net", "zscalerthree.net",
    "zscloud.net", "zscalerbeta.net", "zscalergov.net", "zscalerten.net",
)

# The first message a Secure Client sends: no user, no password, no group.
ANYCONNECT_INIT = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<config-auth client="vpn" type="init" aggregate-auth-version="2">\n'
    '<version who="vpn">{version}</version>\n'
    "<device-id>win</device-id>\n"
    "<group-access>https://{host}/</group-access>\n"
    "<capabilities><auth-method>single-sign-on-v2</auth-method></capabilities>\n"
    "</config-auth>\n"
)

KNOWN_IDP_HOSTS = {
    "login.microsoftonline.com": "Microsoft Entra ID",
    "login.microsoftonline.us": "Microsoft Entra ID (US Gov)",
    "sts.windows.net": "Microsoft Entra ID",
    "accounts.google.com": "Google Workspace",
    "okta.com": "Okta",
    "oktapreview.com": "Okta (preview)",
    "okta-emea.com": "Okta",
    "onelogin.com": "OneLogin",
    "pingidentity.com": "Ping Identity",
    "pingone.com": "Ping Identity (PingOne)",
    "auth0.com": "Auth0",
    "duosecurity.com": "Cisco Duo",
}
ENTRA_HOSTS = ("login.microsoftonline.com", "login.microsoftonline.us", "sts.windows.net")


class Fingerprint:
    def __init__(self, host, timeout=15, verbose=False):
        # self.host keeps any explicit port for URLs; the bare name and port are
        # split out for the raw TLS probe.
        self.host = _normalize_host(host)
        self.hostname, self.port = _split_host_port(self.host)
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": BROWSER_UA})
        self.reachable = False
        self.error = None
        self.products = []
        self.idps = []
        self.notes = []
        self.tls = {}
        self.client_certificate = {}

    def log(self, message):
        if self.verbose:
            print(f"[.] {message}", file=sys.stderr)

    # -- transport ---------------------------------------------------------
    def _request(self, method, path, **kwargs):
        url = urljoin(f"https://{self.host}/", path)
        kwargs.setdefault("timeout", self.timeout)
        try:
            return self.session.request(method, url, verify=False, **kwargs)
        except RequestException as exc:
            self.log(f"{method} {path} failed: {exc}")
            return None

    # -- TLS metadata ------------------------------------------------------
    def probe_tls(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.hostname) as tls:
                    # With CERT_NONE, getpeercert() returns an empty dict, so the
                    # certificate fields are parsed from the DER bytes instead.
                    der = tls.getpeercert(binary_form=True)
                    self.tls = {
                        "tls_version": tls.version(),
                        "cipher": tls.cipher()[0] if tls.cipher() else None,
                        "cert_sha256": hashlib.sha256(der).hexdigest() if der else None,
                    }
                    self.tls.update(_describe_certificate(der))
            self.reachable = True
        except ssl.SSLError as exc:
            # Something is listening; the HTTP probes may still negotiate.
            self.log(f"TLS probe failed: {exc}")
            self.tls = {"error": str(exc)}
            self.reachable = True
        except (OSError, ValueError) as exc:
            self.log(f"connection failed: {exc}")
            self.error = str(exc)

    # -- TLS client-certificate request ------------------------------------
    def probe_client_certificate(self):
        """What the server asks of a client certificate, at the TLS layer."""
        found = client_cert_probe.probe(self.hostname, self.port, self.timeout, self.log)
        self.client_certificate = found
        if found.get("error"):
            self.log(f"client-certificate probe failed: {found['error']}")
        elif found["ca_names"]:
            self.notes.append("The accepted client-certificate CAs are readable before authentication.")

    # -- GlobalProtect -----------------------------------------------------
    def probe_globalprotect(self):
        found = False
        for role, path in (
            ("portal", "/global-protect/prelogin.esp"),
            ("gateway", "/ssl-vpn/prelogin.esp"),
        ):
            resp = self._request(
                "POST", path, data={"tmp": "tmp", "clientVer": "4100", "clientos": "Windows"}
            )
            body = (resp.text or "") if resp is not None else ""
            if "<prelogin-response>" not in body:
                continue
            message = _xml_text(body, "msg") or ""
            if "does not exist" in message.lower():
                continue  # the box answers, but has no portal / gateway role
            found = True
            product = {"product": f"Palo Alto GlobalProtect ({role})", "endpoint": path}
            region = _xml_text(body, "region")
            if region:
                product["region"] = region
            auth_method, idp = _globalprotect_auth(body, message)
            product["auth_method"] = auth_method
            banner = _xml_text(body, "authentication-message")
            if banner:
                product["auth_message"] = banner
            if idp:
                product["saml_destination"] = idp["url"]
                self._record_idp(idp)
            self.products.append(product)
        if found:
            self.notes.append("GlobalProtect prelogin answered without authentication.")
            self.notes.append("Next: gp_recon.")

    # -- Cisco ASA / Secure Client -----------------------------------------
    def probe_cisco(self):
        endpoints, methods, groups = [], [], []
        product = {"product": "Cisco ASA / Secure Client"}

        # 1. What the client itself asks first. The answer names the login
        #    form, the SSO URL, or a client-certificate request.
        init = self._request(
            "POST", "/",
            data=ANYCONNECT_INIT.format(version=ANYCONNECT_VERSION, host=self.host),
            headers={
                "User-Agent": ANYCONNECT_UA,
                "X-Aggregate-Auth": "1",
                "X-Transcend-Version": "1",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        body = (init.text or "") if init is not None else ""
        if "<config-auth" in body:
            endpoints.append("/ (AnyConnect handshake)")
            groups.extend(_group_list(body))
            if re.search(r"<client-cert-request[\s/>]", body):
                methods.append("certificate requested")
            sso_url = _xml_text(body, "sso-v2-login")
            if sso_url:
                methods.append("SAML")
                idp = self._follow_to_idp(unescape(sso_url))
                if idp:
                    product["saml_destination"] = idp["url"]
                    self._record_idp(idp)
            if re.search(r'<input\b[^>]*type="password"', body):
                methods.append("password")
            if re.search(r"<host-scan[\s/>]", body):
                product["hostscan"] = "posture check runs before login"

        # 2. The browser logon page.
        logon = self._request("GET", "/+CSCOE+/logon.html")
        if logon is not None and logon.status_code < 400 and "webvpn" in (logon.text or "").lower():
            endpoints.append("/+CSCOE+/logon.html")
            for name in _group_list(logon.text):
                if name not in groups:
                    groups.append(name)

        # 3. The HostScan policy, which an ASA commonly serves before login.
        data_xml = self._request("GET", "/CACHE/sdesktop/data.xml")
        if (
            data_xml is not None
            and data_xml.status_code == 200
            and "<hostscan" in (data_xml.text or "").lower()
        ):
            endpoints.append("/CACHE/sdesktop/data.xml")
            product["hostscan_policy"] = "readable at /CACHE/sdesktop/data.xml"
            self.notes.append("Cisco HostScan data.xml readable before authentication.")

        if not endpoints:
            return
        product["endpoint"] = ", ".join(endpoints)
        product["auth_method"] = " + ".join(methods) if methods else "unknown"
        if groups:
            product["tunnel_groups"] = ", ".join(groups)
            self.notes.append("Cisco tunnel-group list is public.")
        # Same key order for every product: endpoint and auth first.
        ordered = {key: product[key] for key in ("product", "endpoint", "auth_method") if key in product}
        ordered.update(product)
        self.products.append(ordered)
        self.notes.append("Next: cisco_profile_lens.")

    # -- Fortinet FortiGate SSL VPN ----------------------------------------
    def probe_fortigate(self):
        endpoints, methods = [], []
        product = {"product": "Fortinet FortiGate SSL VPN"}

        # 1. The web logon page.
        login = self._request("GET", "/remote/login")
        body = (login.text or "") if login is not None else ""
        if login is not None and login.status_code == 200 and any(
            marker in body for marker in ("/remote/logincheck", "fgt_lang", "/sslvpn/")
        ):
            endpoints.append("/remote/login")
            if re.search(r'name=["\']credential["\']', body):
                methods.append("password")

        # 2. What FortiClient asks first.
        info = self._request("GET", "/remote/info")
        if (
            info is not None
            and info.status_code == 200
            and re.search(r"<info>\s*<api\b", info.text or "")
        ):
            endpoints.append("/remote/info")

        if not endpoints:
            return

        # 3. The SSO start URL. With SAML configured it leaves for the IdP;
        #    otherwise it stays on the gateway.
        idp = self._follow_to_idp(f"https://{self.host}/remote/saml/start")
        if idp:
            methods.insert(0, "SAML")
            product["saml_destination"] = idp["url"]
            self._record_idp(idp)

        product["endpoint"] = ", ".join(endpoints)
        product["auth_method"] = " + ".join(methods) if methods else "unknown"
        ordered = {key: product[key] for key in ("product", "endpoint", "auth_method")}
        ordered.update(product)
        self.products.append(ordered)
        self.notes.append("FortiGate SSL VPN logon page answered without authentication.")

    def _record_idp(self, idp):
        key = (idp["host"], idp.get("tenant"))
        if key not in {(item["host"], item.get("tenant")) for item in self.idps}:
            self.idps.append({k: v for k, v in idp.items() if k != "url"})

    def _follow_to_idp(self, url):
        """Follow the gateway's own SSO start URL until it leaves the gateway."""
        for _ in range(4):
            resp = self._request("GET", url, allow_redirects=False)
            if resp is None:
                return None
            location = resp.headers.get("Location", "")
            if location:
                target = urljoin(url, location)
                if (urlparse(target).hostname or "").lower() != self.hostname.lower():
                    return _classify_idp_url(target)
                url = target
                continue
            # No redirect: an auto-submitting form (POST binding).
            match = re.search(r'action="(https?://[^"]+)"', resp.text or "", re.I)
            if match:
                target = unescape(match.group(1))
                if (urlparse(target).hostname or "").lower() != self.hostname.lower():
                    return _classify_idp_url(target)
            return None
        return None

    # -- driver ------------------------------------------------------------
    def run(self):
        self.probe_tls()
        if self.reachable:
            self.probe_client_certificate()
            self.probe_globalprotect()
            self.probe_cisco()
            self.probe_fortigate()
        return self.result()

    def result(self):
        return {
            "host": self.host,
            "reachable": self.reachable,
            "error": self.error,
            "products": self.products,
            "identity_providers": self.idps,
            "tls": self.tls,
            "client_certificate": self.client_certificate,
            "notes": self.notes,
        }


def _globalprotect_auth(body, message):
    """(auth_method, idp) advertised by one prelogin response."""
    lowered = message.lower()
    if "certificate" in lowered and "required" in lowered:
        return "certificate required", None
    saml_request = _xml_text(body, "saml-request")
    if saml_request:
        binding = _xml_text(body, "saml-auth-method")
        method = f"SAML ({binding})" if binding else "SAML"
        return method, _idp_from_saml_request(saml_request)
    if (_xml_text(body, "status") or "").lower() == "success":
        return "password", None
    return "unknown", None


def _group_list(markup):
    """Tunnel-group names from a <select name="group_list"> (XML or HTML)."""
    names = []
    for select in re.findall(
        r'<select\b[^>]*name=["\']group_list["\'][^>]*>(.*?)</select>', markup, re.S | re.I
    ):
        for attrs, text in re.findall(r"<option\b([^>]*)>([^<]*)", select, re.I):
            value = re.search(r'value=["\']([^"\']*)["\']', attrs, re.I)
            name = unescape((value.group(1) if value else text).strip())
            if name and name not in names:
                names.append(name)
    return names


def _normalize_host(value):
    value = value.strip()
    if "://" in value:
        value = urlparse(value).netloc or urlparse(value).path
    return value.split("/")[0].strip()


def _split_host_port(host):
    """Split 'name', 'name:8443' or '[v6]:8443' into (name, port)."""
    parsed = urlparse(f"//{host}")
    try:
        port = parsed.port
    except ValueError:
        port = None
    return parsed.hostname or host, port or 443


def _describe_certificate(der):
    """Subject/issuer/SAN/expiry of a DER certificate, without validating it."""
    if not der:
        return {}
    try:
        from cryptography import x509
    except ImportError:
        return {"note": "install 'cryptography' for subject/issuer/SAN details"}
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError:
        return {}
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = san.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        names = []
    expires = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "san": names,
        "not_after": expires.isoformat(),
    }


def _xml_text(body, tag):
    # The tag name must end at whitespace or ">": a plain \b would let
    # "saml-request" match <saml-request-timeout>.
    match = re.search(rf"<{tag}(?:\s[^>]*)?>(.*?)</{tag}>", body, re.S | re.I)
    if not match:
        return None
    value = match.group(1).strip()
    cdata = re.fullmatch(r"<!\[CDATA\[(.*)\]\]>", value, re.S)
    if cdata:
        value = cdata.group(1).strip()
    return value or None


def _idp_from_saml_request(saml_request):
    try:
        decoded = base64.b64decode(saml_request)
    except Exception:
        return None
    # The value is a redirect URL, an HTML form, or a (possibly deflated)
    # AuthnRequest.
    candidates = [decoded]
    try:
        candidates.append(zlib.decompress(decoded, -15))
    except zlib.error:
        pass
    for blob in candidates:
        text = blob.decode("utf-8", "replace")
        for pattern in (
            r'Destination="([^"]+)"',
            r'action="(https?://[^"]+)"',
            r"(https?://[^\s\"'<>]+)",
        ):
            match = re.search(pattern, text, re.I)
            if match:
                return _classify_idp_url(unescape(match.group(1)))
    return None


def _classify_idp_url(url):
    host = (urlparse(url).hostname or url).lower()
    idp = {"vendor": "unknown", "host": host, "url": url}
    for known, vendor in KNOWN_IDP_HOSTS.items():
        # Exact host or a real subdomain only: a substring test would label
        # okta.com.attacker.example as Okta.
        if host == known or host.endswith("." + known):
            idp["vendor"] = vendor
            break
    if host in ENTRA_HOSTS:
        tenant = re.search(r"/([0-9a-fA-F-]{36})(?:/|$)", urlparse(url).path)
        if tenant:
            idp["tenant"] = tenant.group(1)
    return idp


def normalize_zscaler_cloud(value):
    """'zscalerthree', 'zscalerthree.net' or 'login.zscalerthree.net' -> 'zscalerthree.net'."""
    cloud = _normalize_host(value).lower()
    for prefix in ("login.", "mobile.", "admin."):
        if cloud.startswith(prefix):
            cloud = cloud[len(prefix):]
    if "." not in cloud:
        cloud += ".net"
    if not re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", cloud):
        raise ValueError(f"invalid Zscaler cloud name: {value!r}")
    return cloud


def zscaler_check(domain, cloud, timeout=15, log=lambda message: None):
    """Ask one Zscaler cloud whether a company domain is registered there.

    Sends the request Zscaler Client Connector sends when a user types their
    email address: login.<cloud>/clstart with the domain. The cloud answers
    "Domain not found", or starts the sign-in for that domain, which reveals
    the identity provider. Returns (product_entry, idp_or_None).
    """
    domain = domain.strip().lower().rsplit("@", 1)[-1]
    if not re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", domain):
        raise ValueError(f"invalid domain: {domain!r}")
    start = f"https://login.{cloud}/clstart"
    entry = {"product": f"Zscaler ({cloud})", "endpoint": start, "domain": domain}
    params = {
        "version": "1",
        "redrurl": f"https://mobile.{cloud}/test.html",
        "code_challenge_method": "S256",
        "_domain": domain,
    }
    session = requests.Session()
    session.headers.update({"User-Agent": ZSCALER_UA})
    url = start
    for hop in range(5):
        try:
            resp = session.get(
                url, params=params if hop == 0 else None,
                allow_redirects=False, timeout=timeout,
            )
        except RequestException as exc:
            log(f"zscaler GET {url} failed: {exc}")
            entry["registered"] = "unknown"
            entry["detail"] = f"request failed: {exc.__class__.__name__}"
            return entry, None

        location = resp.headers.get("Location", "")
        if location:
            target = urljoin(url, location)
            query = parse_qs(urlparse(target).query)
            if "emsg" in query or "ecode" in query:
                message = (query.get("emsg") or [""])[0]
                code = (query.get("ecode") or [""])[0]
                if "not found" in message.lower():
                    entry["registered"] = "no"
                    entry["detail"] = f"{message} on this cloud"
                else:
                    entry["registered"] = "unknown"
                    entry["detail"] = f"{message or 'error'} (ecode {code})"
                return entry, None
            host = (urlparse(target).hostname or "").lower()
            if host == cloud or host.endswith("." + cloud):
                url = target  # still inside the Zscaler cloud; keep following
                continue
            idp = _classify_idp_url(target)
            entry.update(registered="yes", auth_method="SAML (REDIRECT)", saml_destination=target)
            return entry, idp

        body = resp.text or ""
        form = re.search(r'action="(https?://[^"]+)"', body, re.I)
        if form:
            target = unescape(form.group(1))
            host = (urlparse(target).hostname or "").lower()
            if not (host == cloud or host.endswith("." + cloud)):
                idp = _classify_idp_url(target)
                entry.update(registered="yes", auth_method="SAML (POST)", saml_destination=target)
                return entry, idp
        if resp.status_code == 200 and re.search(r'type=["\']password["\']', body, re.I):
            entry.update(registered="yes", auth_method="password (Zscaler-hosted login)")
            return entry, None
        entry["registered"] = "unknown"
        entry["detail"] = f"unexpected answer (HTTP {resp.status_code})"
        return entry, None
    entry["registered"] = "unknown"
    entry["detail"] = "too many redirects inside the Zscaler cloud"
    return entry, None


def print_report(result):
    host = result.get("host")
    print("=" * 70)
    print(f"VPN fingerprint - {host}" if host else "Zscaler domain check")
    print("=" * 70)
    if host and not result["reachable"]:
        print(f"Could not connect: {result['error']}")
        if not result["products"]:
            return
    tls = result.get("tls") or {}
    if tls.get("issuer"):
        print(f"TLS: {tls.get('tls_version')} | issuer: {tls['issuer']}")
    print()
    client_cert = result.get("client_certificate") or {}
    if host and result["reachable"] and not any(
        not product["product"].startswith("Zscaler") for product in result["products"]
    ):
        print("VPN gateway: none recognised (not GlobalProtect, Cisco ASA or FortiGate)")
        if client_cert.get("enforcement") == "required":
            print("  The server refuses TLS without a client certificate, so nothing")
            print("  behind it could be probed.")
        print()
    if result["products"]:
        print("Products:")
        for product in result["products"]:
            marker = "-" if product.get("registered") == "no" else "+"
            print(f"  [{marker}] {product['product']}")
            for key, value in product.items():
                if key != "product":
                    print(f"        {key}: {value}")
    if "requested" in client_cert:
        if result["products"]:
            print()
        print("Client certificate (TLS handshake):")
        if not client_cert["requested"]:
            print("  [-] not requested")
        else:
            print("  [+] requested")
            print(f"        enforcement: {client_cert['enforcement']} - "
                  f"{client_cert['enforcement_detail']}")
            if client_cert["certificate_types"]:
                print(f"        certificate_types: {', '.join(client_cert['certificate_types'])}")
            if not client_cert["ca_names"]:
                print("        accepted_ca: (the server sent an empty list)")
            for name in client_cert["ca_names"]:
                print(f"        accepted_ca: {name}")
    if result["identity_providers"]:
        print()
        print("Identity providers:")
        for idp in result["identity_providers"]:
            extra = f" tenant={idp['tenant']}" if idp.get("tenant") else ""
            print(f"  [+] {idp['vendor']} ({idp['host']}){extra}")
    if result["notes"]:
        print()
        print("Notes:")
        for note in result["notes"]:
            print(f"  - {note}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("host", nargs="?", help="hostname, host:port, or URL of the VPN gateway")
    parser.add_argument("--zscaler", metavar="DOMAIN",
                        help="also ask a Zscaler cloud whether this company domain is registered")
    parser.add_argument("--zscaler-cloud", metavar="CLOUD",
                        help="the Zscaler cloud to ask (required with --zscaler). Known clouds: "
                             + ", ".join(ZSCALER_CLOUDS) + ". Only the one you name is asked.")
    parser.add_argument("--timeout", type=float, default=15, help="per-request timeout in seconds")
    parser.add_argument("--json", metavar="PATH", help="write JSON result (- for stdout)")
    parser.add_argument("--verbose", action="store_true", help="log each failed probe to stderr")
    args = parser.parse_args(argv)
    if not args.host and not args.zscaler:
        parser.error("give a VPN host, --zscaler DOMAIN, or both")
    if bool(args.zscaler) != bool(args.zscaler_cloud):
        parser.error("--zscaler and --zscaler-cloud must be used together")

    # Verification is off on purpose (see README); one warning per request is noise.
    try:
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    if args.host:
        result = Fingerprint(args.host, timeout=args.timeout, verbose=args.verbose).run()
    else:
        result = {"host": None, "reachable": True, "error": None, "products": [],
                  "identity_providers": [], "tls": {}, "client_certificate": {}, "notes": []}

    if args.zscaler:
        def log(message):
            if args.verbose:
                print(f"[.] {message}", file=sys.stderr)
        try:
            entry, idp = zscaler_check(
                args.zscaler, normalize_zscaler_cloud(args.zscaler_cloud),
                timeout=args.timeout, log=log,
            )
        except ValueError as exc:
            parser.error(str(exc))
        result["products"].append(entry)
        if idp:
            known = {(item["host"], item.get("tenant")) for item in result["identity_providers"]}
            if (idp["host"], idp.get("tenant")) not in known:
                result["identity_providers"].append({k: v for k, v in idp.items() if k != "url"})

    if args.json:
        payload = json.dumps(result, indent=2)
        if args.json == "-":
            print(payload)
        else:
            with open(args.json, "w", encoding="utf-8") as handle:
                handle.write(payload)
            print(f"[+] wrote {args.json}", file=sys.stderr)
    else:
        print_report(result)
    return 0 if result["reachable"] else 1


if __name__ == "__main__":
    sys.exit(main())
