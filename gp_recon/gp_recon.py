#!/usr/bin/env python3
"""GlobalProtect Recon - what does this portal ask of a client?

    gp_recon.py portal.example.com

Give it the portal. It asks the portal how it authenticates and tells you what
it needs: a username and password, a client certificate, or a SAML sign-in
(done in a Chromium window, or through saml_bridge with --proxy for a PRT
handoff). After sign-in it fetches the portal configuration and reports the
gateways, the HIP categories the portal collects, and whether a client-side
check (CSC) is required, writing review templates for both.

It identifies itself as stock OpenConnect does (User-Agent "PAN GlobalProtect",
clientVer 4100, os-version "win"); those values are fixed.

It never connects to a gateway and never submits a HIP report. The one thing it
submits besides credentials is the CSC report you reviewed and selected with
--csc-template. Authorized use only.
"""

import argparse
import asyncio
import base64
from contextlib import contextmanager
from datetime import datetime
import getpass
import hashlib
import os
import re
import signal
import socket
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from html import unescape as html_unescape
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, quote_plus, unquote, urljoin, urlparse
from xml.sax.saxutils import escape


PORTAL = ""
# Request identity of stock OpenConnect (`openconnect --protocol=gp --os=win`):
# the fixed User-Agent, clientVer, and the platform name as os-version.
OPENCONNECT_USER_AGENT = "PAN GlobalProtect"
CLIENT_VERSION = "4100"
CLIENT_OS = "Windows"       # OpenConnect's name for --os=win
OS_VERSION_VALUE = "win"    # OpenConnect sends the platform name as os-version
OUTPUT_DIR = Path("gp_recon_output")
SIGN_IN_TIMEOUT_SECONDS = 300
BROWSER_STEP_DELAY_SECONDS = 2.0
CSC_TEMPLATE_DIR = Path(__file__).resolve().parent / "csc_templates"
HIP_TEMPLATE_DIR = Path(__file__).resolve().parent / "hip_templates"
BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
)
CSC_DIGEST_PLACEHOLDER = "__#_PAN_CSC_DATA_DIGEST_#__"

# Configured by main().
client_cert = None
ca_cert = None
proxy_url = None
save_raw_responses = False
verbose_mode = False
csc_variables = {}
csc_template_path = None
last_generated_hip_template = None
last_config_xml = None
csc_state = "not required"
user_name = None
host_id = None
device_serial = None


class ReviewRequired(RuntimeError):
    pass


class CredentialRejected(RuntimeError):
    """The identity provider or portal rejected a supplied password."""


def _vprint(message):
    if verbose_mode:
        print(message, flush=True)


def _configure_console_output():
    """Make progress output visible immediately through pipes and supervisors."""
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        try:
            reconfigure(line_buffering=True, write_through=True)
        except (OSError, TypeError, ValueError):
            pass


def _handle_termination_signal(_signum, _frame):
    raise KeyboardInterrupt

USERNAME_SELECTORS = (
    'input[name="loginfmt"]',
    'input[name="username"]',
    'input[name="identifier"]',
    "#okta-signin-username",
    "#i0116",
    'input[type="email"]',
    'input[autocomplete="username"]',
)
PASSWORD_SELECTORS = (
    'input[name="passwd"]',
    'input[name="password"]',
    'input[name="credentials.passcode"]',
    "#okta-signin-password",
    "#i0118",
    'input[type="password"]',
    'input[autocomplete="current-password"]',
)
OTP_SELECTORS = (
    'input[name="otc"]',
    "#idTxtBx_SAOTCC_OTC",
    'input[name="VerificationCode"]',
    'input[autocomplete="one-time-code"]',
)
NUMBER_MATCH_SELECTORS = (
    "#idRichContext_DisplaySign",
    '[data-testid="numberMatch"]',
    '[data-bind*="displaySign"]',
)
ERROR_SELECTORS = (
    "#usernameError",
    "#passwordError",
    "#idTD_Error",
    "#idDiv_SAOTCC_ErrorMsg_OTC",
    '[role="alert"]',
)
SUBMIT_SELECTORS = (
    "#idSIButton9",
    'button[type="submit"]',
    'input[type="submit"]',
    'button[data-testid="primaryButton"]',
    'button[data-test-id="primaryButton"]',
)


def _load_requests():
    try:
        import requests
    except ImportError as exc:
        raise RuntimeError(
            "Missing Python dependency 'requests' (install it with: pip install requests)"
        ) from exc
    if proxy_url:
        # Proxy mode intentionally sets verify=False. Keep the script's single,
        # explicit warning while suppressing urllib3's warning on every request.
        try:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except ImportError:
            requests.packages.urllib3.disable_warnings(
                requests.packages.urllib3.exceptions.InsecureRequestWarning
            )
    return requests


def _load_cryptography():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import pkcs12
    except ImportError as exc:
        raise RuntimeError(
            "PFX and encrypted PEM support requires 'cryptography' "
            "(install it with: pip install cryptography)"
        ) from exc
    return serialization, pkcs12


def _gp_tls_options():
    options = {"verify": False if proxy_url else (str(ca_cert) if ca_cert else True)}
    if proxy_url:
        options["proxies"] = {"http": proxy_url, "https": proxy_url}
    if client_cert:
        options["cert"] = client_cert
    return options


def _idp_tls_options():
    """Return proxy/TLS options without exposing the GP client certificate."""
    if not proxy_url:
        return {"verify": True}
    return {
        "verify": False,
        "proxies": {"http": proxy_url, "https": proxy_url},
    }


def _gp_request(request_callable, url, **kwargs):
    """Make a GlobalProtect request with mTLS and a useful TLS error."""
    requests = _load_requests()
    kwargs.update(_gp_tls_options())
    try:
        return request_callable(url, **kwargs)
    except requests.exceptions.SSLError as exc:
        if client_cert:
            hint = (
                "A client certificate was supplied, but TLS failed. Check that the "
                "certificate and private key match, that the PFX password is correct, "
                "and that the issuing CA is accepted by the portal. If the portal's "
                "server certificate uses a private CA, provide --ca-cert."
            )
        else:
            hint = (
                "No client certificate was supplied. Provide --client-pfx or "
                "--client-cert/--client-key if the portal requires mTLS. If only the "
                "portal's server certificate is untrusted, provide --ca-cert."
            )
        raise RuntimeError(f"TLS certificate error connecting to {url}: {exc}. {hint}") from exc


@contextmanager
def _prepared_client_certificate(args):
    """Yield a requests-compatible cert path/tuple, converting when necessary."""
    if not args.client_pfx and not args.client_cert:
        yield None
        return

    with tempfile.TemporaryDirectory(prefix="gp-auth-cert-") as temporary_dir:
        temporary_dir = Path(temporary_dir)

        if args.client_pfx:
            serialization, pkcs12 = _load_cryptography()
            pfx_data = args.client_pfx.read_bytes()
            try:
                private_key, certificate, additional = pkcs12.load_key_and_certificates(
                    pfx_data, None
                )
            except ValueError:
                password = getpass.getpass(f"PFX password ({args.client_pfx}): ")
                if not password:
                    raise RuntimeError("A PFX password is required")
                try:
                    private_key, certificate, additional = (
                        pkcs12.load_key_and_certificates(
                            pfx_data, password.encode("utf-8")
                        )
                    )
                except ValueError as exc:
                    raise RuntimeError(
                        "Unable to open the PFX; the password may be incorrect"
                    ) from exc
                finally:
                    password = ""

            if private_key is None or certificate is None:
                raise RuntimeError("The PFX must contain a certificate and private key")
            pem = certificate.public_bytes(serialization.Encoding.PEM)
            for chain_certificate in additional or ():
                pem += chain_certificate.public_bytes(serialization.Encoding.PEM)
            pem += private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
            combined_path = temporary_dir / "client-cert.pem"
            _write_private_file(combined_path, pem)
            yield str(combined_path)
            return

        certificate_path = args.client_cert
        if not args.client_key:
            combined_data = certificate_path.read_bytes()
            if b"ENCRYPTED" not in combined_data:
                yield str(certificate_path)
                return

            key_match = re.search(
                rb"-----BEGIN (?:ENCRYPTED |RSA |EC )?PRIVATE KEY-----.*?"
                rb"-----END (?:ENCRYPTED |RSA |EC )?PRIVATE KEY-----\s*",
                combined_data,
                re.DOTALL,
            )
            if not key_match:
                raise RuntimeError(
                    "The combined PEM appears encrypted, but its private-key block "
                    "could not be found"
                )
            serialization, _ = _load_cryptography()
            password = getpass.getpass(
                f"Private-key password ({certificate_path}): "
            )
            if not password:
                raise RuntimeError("A private-key password is required")
            try:
                private_key = serialization.load_pem_private_key(
                    key_match.group(0), password=password.encode("utf-8")
                )
            except (TypeError, ValueError) as exc:
                raise RuntimeError(
                    "Unable to open the PEM private key; the password may be incorrect"
                ) from exc
            finally:
                password = ""
            decrypted_combined_path = temporary_dir / "client-combined.pem"
            decrypted_key = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
            decrypted_combined = (
                combined_data[: key_match.start()]
                + combined_data[key_match.end() :]
                + decrypted_key
            )
            _write_private_file(decrypted_combined_path, decrypted_combined)
            yield str(decrypted_combined_path)
            return

        key_data = args.client_key.read_bytes()
        if b"ENCRYPTED" not in key_data:
            yield (str(certificate_path), str(args.client_key))
            return

        serialization, _ = _load_cryptography()
        password = getpass.getpass(f"Private-key password ({args.client_key}): ")
        if not password:
            raise RuntimeError("A private-key password is required")
        try:
            private_key = serialization.load_pem_private_key(
                key_data, password=password.encode("utf-8")
            )
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                "Unable to open the PEM private key; the password may be incorrect"
            ) from exc
        finally:
            password = ""
        decrypted_key_path = temporary_dir / "client-key.pem"
        _write_private_file(
            decrypted_key_path,
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ),
        )
        yield (str(certificate_path), str(decrypted_key_path))


def _write_private_file(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = content if isinstance(content, bytes) else content.encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


def _ask_password(prompt):
    password = getpass.getpass(prompt)
    if not password:
        raise RuntimeError("An empty password was entered")
    return password


def _parse_csc_variables(command_line_values):
    values = {}
    for item in command_line_values or ():
        name, separator, value = item.partition("=")
        if not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise RuntimeError(
                f"Invalid CSC variable {item!r}; expected NAME=VALUE"
            )
        values[name] = value
    return values


def _normalize_gp_server_url(value, label):
    value = (value or "").strip()
    if not value:
        return None
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise RuntimeError(
            f"{label} must be a hostname or HTTP(S) URL, for example "
            f"vpn.example.com"
        )
    if re.search(r"[\\\s]", parsed.netloc):
        raise RuntimeError(
            f"{label} contains an invalid hostname character: {parsed.netloc!r}; "
            "do not escape dots with backslashes"
        )

    path = parsed.path.rstrip("/")
    for marker in ("/global-protect", "/ssl-vpn"):
        marker_position = path.lower().find(marker)
        if marker_position >= 0:
            path = path[:marker_position]
            break
    if path:
        raise RuntimeError(
            f"{label} must identify the GlobalProtect server, without an unrelated "
            f"URL path: {value}"
        )
    return f"{parsed.scheme.lower()}://{parsed.netloc}"


def _extract_text(xml_text, tag):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        root = None
    if root is not None:
        wanted = tag.lower()
        for element in root.iter():
            local_name = element.tag.rsplit("}", 1)[-1].rsplit(":", 1)[-1]
            if local_name.lower() != wanted:
                continue
            value = "".join(element.itertext()).strip()
            return html_unescape(value) if value else None

    match = re.search(
        rf"<(?:[A-Za-z_][\w.-]*:)?{re.escape(tag)}\b[^>]*>(.*?)"
        rf"</(?:[A-Za-z_][\w.-]*:)?{re.escape(tag)}\s*>",
        xml_text,
        re.DOTALL | re.IGNORECASE,
    )
    if not match:
        return None
    value = match.group(1).strip()
    cdata = re.fullmatch(r"<!\[CDATA\[(.*)\]\]>", value, re.DOTALL)
    if cdata:
        value = cdata.group(1).strip()
    return html_unescape(value) if value else None


def _extract_xml_fragment(xml_text, tag):
    match = re.search(
        rf"<(?:[A-Za-z_][\w.-]*:)?{re.escape(tag)}\b[^>]*>.*?"
        rf"</(?:[A-Za-z_][\w.-]*:)?{re.escape(tag)}\s*>",
        xml_text,
        re.DOTALL | re.IGNORECASE,
    )
    return match.group(0).strip() if match else None


def _xml_local_name(tag):
    return tag.rsplit("}", 1)[-1].rsplit(":", 1)[-1]


def _versioned_output_path(directory, filename):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    candidate = directory / filename
    if not candidate.exists():
        return candidate
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    versioned = candidate.with_name(
        f"{candidate.stem}_{timestamp}{candidate.suffix}"
    )
    counter = 2
    while versioned.exists():
        versioned = candidate.with_name(
            f"{candidate.stem}_{timestamp}_{counter}{candidate.suffix}"
        )
        counter += 1
    return versioned


def _csc_value_placeholder(registry_path, value_name):
    normalized = re.sub(
        r"[^A-Za-z0-9]+", "_", f"{registry_path}_{value_name}"
    ).strip("_")
    return "{{REG_" + normalized.upper() + "_VALUE}}"


def generate_csc_template(config_criteria_xml, template_directory):
    try:
        criteria_root = ET.fromstring(config_criteria_xml)
    except ET.ParseError as exc:
        raise RuntimeError(f"Unable to parse portal CSC criteria: {exc}") from exc

    report = ET.Element("hip-report")
    for tag, value in (
        ("portal-csc-auth-cookie", "{{PORTAL_CSC_AUTH_COOKIE}}"),
        ("user-name", "{{USERNAME}}"),
        ("client-os", "{{CLIENT_OS}}"),
        ("host-id", "{{HOST_ID}}"),
        ("device-serial-number", "{{DEVICE_SERIAL_NUMBER}}"),
        ("csc-digest", "{{CSC_DIGEST}}"),
    ):
        ET.SubElement(report, tag).text = value
    ET.SubElement(report, "categories")
    output_custom_checks = ET.SubElement(report, "custom-checks")
    output_registry = ET.SubElement(output_custom_checks, "registry-key")

    registry_entries = []
    for element in criteria_root.iter():
        if _xml_local_name(element.tag) != "registry-key":
            continue
        registry_entries.extend(
            child
            for child in element
            if _xml_local_name(child.tag) == "entry" and child.get("name")
        )

    for required_entry in registry_entries:
        registry_path = required_entry.get("name")
        report_entry = ET.SubElement(output_registry, "entry", {"name": registry_path})
        ET.SubElement(report_entry, "exist").text = "yes"
        ET.SubElement(report_entry, "value").text = ""
        members = []
        for child in required_entry:
            if _xml_local_name(child.tag) != "registry-value":
                continue
            members.extend(
                member.text.strip()
                for member in child
                if _xml_local_name(member.tag) == "member" and member.text
            )
        if members:
            report_values = ET.SubElement(report_entry, "registry-value")
            for member_name in members:
                value_entry = ET.SubElement(
                    report_values, "entry", {"name": member_name}
                )
                ET.SubElement(value_entry, "exist").text = "yes"
                ET.SubElement(value_entry, "value").text = _csc_value_placeholder(
                    registry_path, member_name
                )

    ET.indent(report, space="\t")
    rendered = ET.tostring(report, encoding="unicode")
    path = _versioned_output_path(template_directory, "required_csc.xml")
    _write_private_file(
        path, f'<?xml version="1.0" encoding="UTF-8"?>\n{rendered}\n'
    )
    return path


def generate_hip_template(hip_collection_xml, template_directory):
    try:
        collection = ET.fromstring(hip_collection_xml)
    except ET.ParseError as exc:
        raise RuntimeError(f"Unable to parse portal HIP collection policy: {exc}") from exc

    requested_categories = []
    for element in collection.iter():
        if _xml_local_name(element.tag) != "category":
            continue
        for member in element:
            if _xml_local_name(member.tag) != "member" or not member.text:
                continue
            category = member.text.strip()
            if category and category not in requested_categories:
                requested_categories.append(category)

    report = ET.Element("hip-report", {"name": "hip-report"})
    for tag, value in (
        ("md5-sum", "{{MD5}}"),
        ("user-name", "{{USERNAME}}"),
        ("domain", "{{DOMAIN}}"),
        ("host-name", "{{HOSTNAME}}"),
        ("host-id", "{{HOST_ID}}"),
        ("ip-address", "{{CLIENT_IP}}"),
        ("ipv6-address", "{{CLIENT_IPV6}}"),
        ("generate-time", "{{GENERATE_TIME}}"),
        ("hip-report-version", "4"),
    ):
        ET.SubElement(report, tag).text = value
    categories = ET.SubElement(report, "categories")
    for category in requested_categories:
        entry = ET.SubElement(categories, "entry", {"name": category})
        if category == "host-info":
            ET.SubElement(entry, "client-version").text = "{{APP_VERSION}}"
            ET.SubElement(entry, "os").text = "{{OS_VERSION}}"
            ET.SubElement(entry, "os-vendor").text = "Microsoft"
            ET.SubElement(entry, "host-name").text = "{{HOSTNAME}}"
            ET.SubElement(entry, "host-id").text = "{{HOST_ID}}"
        else:
            ET.SubElement(entry, "list")

    ET.indent(report, space="\t")
    rendered = ET.tostring(report, encoding="unicode")
    path = _versioned_output_path(template_directory, "required_hip.xml")
    _write_private_file(
        path, f'<?xml version="1.0" encoding="UTF-8"?>\n{rendered}\n'
    )
    return path


def _save_response_artifacts(xml_text, response_name, output_dir):
    output_dir = Path(output_dir)
    if save_raw_responses:
        raw_path = _versioned_output_path(
            output_dir / "raw_responses", f"{response_name}.xml"
        )
        _write_private_file(raw_path, xml_text)
        print(f"[*] Raw response saved to {raw_path}")

    for tag in ("config-criteria", "hip-collection"):
        fragment = _extract_xml_fragment(xml_text, tag)
        if not fragment:
            continue
        extracted_path = _versioned_output_path(
            output_dir / "extracted", f"{tag}.xml"
        )
        extracted_xml = f'<?xml version="1.0" encoding="UTF-8"?>\n{fragment}\n'
        _write_private_file(extracted_path, extracted_xml)
        _vprint(f"[*] Extracted <{tag}> saved to {extracted_path}")


def discover_portal_authentication():
    """Return the portal's advertised authentication method and optional IdP URL."""
    requests = _load_requests()
    response = _gp_request(
        requests.post,
        f"{PORTAL}/global-protect/prelogin.esp",
        params={"tmp": "tmp", "clientVer": CLIENT_VERSION, "clientos": CLIENT_OS},
        headers={"User-Agent": OPENCONNECT_USER_AGENT},
        data={"cas-support": "yes"},
        timeout=30,
    )
    response.raise_for_status()
    _save_response_artifacts(response.text, "prelogin_discovery", output_dir)

    message = " ".join(
        value
        for value in (
            _extract_text(response.text, "msg"),
            _extract_text(response.text, "newmsg"),
        )
        if value
    ).strip()
    status = (_extract_text(response.text, "status") or "").lower()
    if "certificate" in message.lower() and "required" in message.lower():
        return {"method": "certificate", "message": message, "response": response.text}

    saml_request = _extract_text(response.text, "saml-request")
    if saml_request:
        saml_start = _parse_saml_request(response.text)
        _vprint(f"[*] Decoded SAML URL: {saml_start['initial_destination']}")
        _vprint("[*] Following SAML redirect to identify the IdP...")
        idp_url = _resolve_idp_destination(saml_start)
        return {
            "method": "saml",
            "login_url": saml_start["browser_url"],
            "saml_start": saml_start,
            "idp_url": idp_url,
            "microsoft_idp": _is_microsoft_idp(idp_url),
            "message": message,
            "response": response.text,
        }

    if status == "success":
        return {"method": "password", "message": message, "response": response.text}
    if "portal does not exist" in message.lower():
        raise RuntimeError(
            "The server reports that no GlobalProtect portal exists at "
            f"{PORTAL}/global-protect/prelogin.esp. Give the portal hostname, "
            "not a gateway hostname."
        )
    raise RuntimeError(
        f"Unable to determine portal authentication method: {message or 'unknown error'}"
    )


def _prompt_for_client_certificate(args):
    certificate_path = input("Client certificate path (PFX/P12 or PEM): ").strip()
    if not certificate_path:
        raise RuntimeError("Client certificate is required")
    certificate_path = Path(certificate_path).expanduser()
    if not certificate_path.is_file():
        raise RuntimeError(f"Client certificate does not exist: {certificate_path}")
    if certificate_path.suffix.lower() in {".pfx", ".p12", ".pkcs12"}:
        args.client_pfx = certificate_path
        args.client_cert = None
        args.client_key = None
        return
    args.client_cert = certificate_path
    key_path = input(
        "Private-key path (leave empty if included in the PEM): "
    ).strip()
    args.client_key = Path(key_path).expanduser() if key_path else None
    if args.client_key and not args.client_key.is_file():
        raise RuntimeError(f"Client private key does not exist: {args.client_key}")


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self._current = None

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag.lower() == "form":
            self._current = {
                "action": attributes.get("action", ""),
                "method": attributes.get("method", "post").lower(),
                "fields": {},
            }
            self.forms.append(self._current)
        elif tag.lower() == "input" and self._current is not None:
            name = attributes.get("name")
            if name:
                self._current["fields"][name] = attributes.get("value", "")

    def handle_endtag(self, tag):
        if tag.lower() == "form":
            self._current = None


def _find_saml_form(html_text):
    parser = _FormParser()
    parser.feed(html_text)
    for form in parser.forms:
        if any(name.lower() == "samlresponse" for name in form["fields"]):
            return form
    return None


def _as_http_url(value):
    value = html_unescape(value or "").strip().strip("\"'")
    parsed = urlparse(value)
    if parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
        return value
    decoded = unquote(value)
    if decoded != value:
        parsed = urlparse(decoded)
        if parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
            return decoded
    return None


def _decode_saml_value(value):
    value = html_unescape(value or "").strip()
    if value.startswith("data:text/html;base64,"):
        value = value.partition(",")[2]
    compact_values = [re.sub(r"\s+", "", value)]
    percent_decoded = unquote(value)
    if percent_decoded != value:
        compact_values.append(re.sub(r"\s+", "", percent_decoded))
    decoders = (
        lambda item: base64.b64decode(item, validate=True),
        base64.urlsafe_b64decode,
    )
    for compact in compact_values:
        padded = compact + "=" * (-len(compact) % 4)
        for decoder in decoders:
            try:
                return decoder(padded).decode("utf-8-sig")
            except (ValueError, UnicodeDecodeError, base64.binascii.Error):
                continue
    return value


def _first_form(html_text):
    parser = _FormParser()
    parser.feed(html_text)
    return parser.forms[0] if parser.forms else None


def _find_url_in_document(document):
    direct = _as_http_url(document)
    if direct:
        return direct
    form = _first_form(document)
    if form:
        action = _as_http_url(form["action"])
        if action:
            return action
    attribute_match = re.search(
        r"(?:href|action|location|url|content)\s*[=:]\s*[\"']?"
        r"(https?://[^\s\"'<>]+)",
        document,
        re.IGNORECASE,
    )
    if attribute_match:
        return _as_http_url(attribute_match.group(1))
    url_match = re.search(r"https?://[^\s\"'<>]+", document, re.IGNORECASE)
    return _as_http_url(url_match.group(0)) if url_match else None


def _parse_saml_request(prelogin_xml):
    raw_value = _extract_text(prelogin_xml, "saml-request")
    if not raw_value:
        raise RuntimeError("GlobalProtect prelogin response did not contain a SAML request")
    method = (_extract_text(prelogin_xml, "saml-auth-method") or "REDIRECT").upper()

    direct_url = _as_http_url(raw_value)
    decoded = direct_url or _decode_saml_value(raw_value)
    decoded_url = _as_http_url(decoded)
    if decoded_url:
        return {
            "method": "GET",
            "request_url": decoded_url,
            "request_fields": {},
            "browser_url": decoded_url,
            "initial_destination": decoded_url,
            "portal_method": method,
        }

    form = _first_form(decoded)
    destination = _find_url_in_document(decoded)
    if form and destination:
        encoded_html = base64.b64encode(decoded.encode("utf-8")).decode("ascii")
        return {
            "method": form["method"].upper(),
            "request_url": destination,
            "request_fields": form["fields"],
            "browser_url": f"data:text/html;base64,{encoded_html}",
            "initial_destination": destination,
            "portal_method": method,
        }
    if destination:
        return {
            "method": "GET",
            "request_url": destination,
            "request_fields": {},
            "browser_url": destination,
            "initial_destination": destination,
            "portal_method": method,
        }
    raise RuntimeError(
        "Portal returned a SAML request, but no redirect URL or HTML form "
        "destination could be found inside it"
    )


def _request_saml_start(session, saml_start):
    method = saml_start["method"]
    request_kwargs = {
        "allow_redirects": True,
        "timeout": 30,
        **_idp_tls_options(),
    }
    if method == "GET":
        request_kwargs["params"] = saml_start["request_fields"]
    else:
        request_kwargs["data"] = saml_start["request_fields"]
    response = session.request(method, saml_start["request_url"], **request_kwargs)
    response.raise_for_status()
    return response


def _resolve_idp_destination(saml_start):
    requests = _load_requests()
    session = requests.Session()
    session.headers.update({"User-Agent": BROWSER_USER_AGENT})
    try:
        response = _request_saml_start(session, saml_start)
    except Exception as exc:
        destination = saml_start["initial_destination"]
        if verbose_mode:
            print(
                f"[!] Could not resolve the SAML redirect beyond {destination}: "
                f"{exc}. Using its embedded destination."
            )
        else:
            print(
                "[!] Could not resolve the SAML redirect; using its embedded "
                "destination. Use --verbose for details."
            )
        return destination
    return response.url


def _is_microsoft_idp(url):
    hostname = (urlparse(url).hostname or "").lower()
    return any(
        hostname == domain or hostname.endswith("." + domain)
        for domain in (
            "microsoftonline.com",
            "microsoftonline.us",
            "microsoftonline.de",
            "microsoftonline.cn",
            "microsoft.com",
            "windows.net",
            "chinacloudapi.cn",
            "live.com",
        )
    )


def _parse_cookie_file(cookie_file):
    raw = Path(cookie_file).read_text(encoding="utf-8").strip()
    if not raw:
        raise RuntimeError(f"Cookie file is empty: {cookie_file}")

    cookies = {}
    for item in re.split(r"[,\r\n]+", raw):
        item = item.strip()
        if not item:
            continue
        name, separator, value = item.partition("=")
        if not separator or not name.strip():
            raise RuntimeError(
                f"Invalid cookie entry {item!r}; expected cookie_name=value"
            )
        cookies[name.strip()] = value.strip()
    if not cookies:
        raise RuntimeError(f"No cookies were found in {cookie_file}")
    return cookies


def requests_saml_login(saml_start, idp_url, cookies):
    """Use existing IdP cookies to obtain and submit the SAML response."""
    requests = _load_requests()
    session = requests.Session()
    session.headers.update({"User-Agent": BROWSER_USER_AGENT})
    login_host = urlparse(idp_url).hostname
    if not login_host:
        raise RuntimeError(f"SAML IdP URL has no hostname: {idp_url}")
    for name, value in cookies.items():
        # Scope identity cookies to the IdP so they are never sent to the
        # GlobalProtect ACS host when the SAML form is submitted.
        session.cookies.set(
            name,
            value,
            domain=login_host,
            path="/",
            secure=idp_url.lower().startswith("https://"),
        )

    response = _request_saml_start(session, saml_start)
    saml_form = _find_saml_form(response.text)
    if not saml_form:
        raise RuntimeError(
            "The supplied cookie did not produce an authenticated SAML response. "
            "It may be expired, bound to another device, or blocked by Conditional Access."
        )

    acs_url = urljoin(response.url, saml_form["action"])
    if saml_form["method"] == "get":
        acs_response = _gp_request(
            session.get,
            acs_url,
            params=saml_form["fields"],
            headers={"User-Agent": OPENCONNECT_USER_AGENT, "Referer": response.url},
            allow_redirects=True,
            timeout=30,
        )
    else:
        acs_response = _gp_request(
            session.post,
            acs_url,
            data=saml_form["fields"],
            headers={"User-Agent": OPENCONNECT_USER_AGENT, "Referer": response.url},
            allow_redirects=True,
            timeout=30,
        )
    acs_response.raise_for_status()
    return acs_response.text


async def _first_visible(page, selectors):
    for selector in selectors:
        locator = page.locator(selector).first
        try:
            if await locator.is_visible(timeout=100):
                return locator
        except Exception:
            pass
    return None


async def _click_first_visible(page, selectors):
    locator = await _first_visible(page, selectors)
    if locator is None:
        return False
    await locator.click()
    return True


async def _submit_input(page, input_locator, selectors=SUBMIT_SELECTORS):
    if await _click_first_visible(page, selectors):
        return
    await input_locator.press("Enter")


async def _visible_error(page):
    for selector in ERROR_SELECTORS:
        locator = page.locator(selector).first
        try:
            if await locator.is_visible(timeout=100):
                message = (await locator.inner_text()).strip()
                if message:
                    return message
        except Exception:
            pass
    return None


def _looks_like_password_rejection(message):
    normalized = " ".join((message or "").casefold().split())
    return any(
        marker in normalized
        for marker in (
            "aadsts50126",
            "account or password is incorrect",
            "incorrect username or password",
            "invalid username or password",
            "password is incorrect",
            "incorrect password",
            "wrong password",
        )
    )


async def _choose_authenticator_method(page):
    patterns = (
        re.compile(r"Microsoft Authenticator", re.IGNORECASE),
        re.compile(r"Approve a request", re.IGNORECASE),
        re.compile(r"Send notification", re.IGNORECASE),
    )
    for pattern in patterns:
        locator = page.get_by_text(pattern).first
        try:
            if await locator.is_visible(timeout=100):
                await locator.click()
                return True
        except Exception:
            pass
    return False


async def _choose_microsoft_account(page, username):
    """Handle Microsoft's account picker before the username/password form."""
    for selector in (
        "#tilesHolder",
        '[data-testid="account-picker"]',
        '[data-test-id="account-picker"]',
    ):
        try:
            picker = page.locator(selector).first
            if not await picker.is_visible(timeout=100):
                continue
            account = picker.get_by_text(username, exact=True).first
            if await account.is_visible(timeout=100):
                await account.click()
                return True
        except Exception:
            pass
    return await _click_first_visible(
        page,
        (
            "#otherTileText",
            '[data-test-id="otherTile"]',
            '[data-testid="otherTile"]',
        ),
    )


def _authenticator_number_from_text(page_text):
    if not re.search(r"authenticator|approve|sign[ -]?in", page_text, re.IGNORECASE):
        return None
    for pattern in (
        r"(?:enter|type)\s+(?:the\s+)?(?:following\s+)?number.{0,200}?\b(\d{2,3})\b",
        r"number\s+shown.{0,200}?\b(\d{2,3})\b",
    ):
        match = re.search(pattern, page_text, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1)
    standalone_numbers = re.findall(r"(?m)^\s*(\d{2,3})\s*$", page_text)
    if len(standalone_numbers) == 1:
        return standalone_numbers[0]
    return None


async def _visible_action_labels(page):
    labels = []
    try:
        actions = page.locator('button, input[type="submit"]')
        for index in range(min(await actions.count(), 20)):
            item = actions.nth(index)
            if await item.is_visible(timeout=50):
                label = (await item.inner_text()).strip()
                if not label:
                    label = (await item.get_attribute("value") or "").strip()
                if label:
                    labels.append(re.sub(r"\s+", " ", label)[:80])
    except Exception:
        pass
    return labels


async def _browser_page_state(page):
    """Return non-secret page diagnostics for verbose stalled-login output."""
    try:
        title = (await page.title()).strip() or "(no title)"
    except Exception:
        title = "(title unavailable)"
    parsed = urlparse(page.url)
    safe_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    visible_inputs = []
    try:
        inputs = page.locator("input")
        for index in range(min(await inputs.count(), 20)):
            item = inputs.nth(index)
            if await item.is_visible(timeout=50):
                input_type = await item.get_attribute("type") or "text"
                input_name = await item.get_attribute("name") or "unnamed"
                visible_inputs.append(f"{input_type}:{input_name}")
    except Exception:
        pass
    inputs_text = ", ".join(visible_inputs) if visible_inputs else "none"
    visible_actions = await _visible_action_labels(page)
    actions_text = ", ".join(visible_actions) if visible_actions else "none"
    return (
        f"page={safe_url}, title={title!r}, visible-inputs={inputs_text}, "
        f"visible-actions={actions_text}"
    )


async def _complete_microsoft_login(
    page,
    username,
    captured,
):
    timeout_seconds = SIGN_IN_TIMEOUT_SECONDS
    deadline = time.monotonic() + timeout_seconds
    username_submitted = False
    password_submitted = False
    password_submitted_at = None
    password_enter_retried_at = None
    otp_submitted = False
    authenticator_selected = False
    account_picker_selected = False
    printed_push_message = False
    displayed_number = None
    next_authenticator_reminder = None
    next_page_state_report = time.monotonic()

    while not captured:
        now = time.monotonic()
        if now >= deadline:
            if displayed_number or printed_push_message:
                decision = await asyncio.to_thread(
                    input,
                    "Still waiting for Authenticator approval. Press Enter to "
                    "continue waiting or type q to cancel: ",
                )
                if decision.strip().lower() in {"q", "quit", "cancel"}:
                    raise RuntimeError("Authenticator approval cancelled")
                deadline = time.monotonic() + timeout_seconds
                next_authenticator_reminder = time.monotonic() + 30
                continue
            break
        if (
            next_authenticator_reminder is not None
            and now >= next_authenticator_reminder
        ):
            print("[*] Still waiting for Microsoft Authenticator approval...")
            next_authenticator_reminder = now + 30
        if verbose_mode and now >= next_page_state_report:
            state = await _browser_page_state(page)
            _vprint(f"[*] Microsoft sign-in state: {state}")
            next_page_state_report = now + 10

        # Microsoft can expose a visible username/alert element on the password
        # page. Handle the actionable password field first so the normal
        # "Please enter your password" prompt is not mistaken for a failed
        # authentication or submitted as an empty form.
        password_input = await _first_visible(page, PASSWORD_SELECTORS)
        username_input = await _first_visible(page, USERNAME_SELECTORS)
        action_labels = await _visible_action_labels(page)
        username_next_stage = any(
            label.strip().casefold() in {"next", "continue"}
            for label in action_labels
        )
        password_submit_stage = any(
            label.strip().casefold() in {"sign in", "signin", "log in", "login"}
            for label in action_labels
        )

        if (
            username_input is not None
            and password_input is not None
            and not username_submitted
            and not username_next_stage
            and not password_submit_stage
        ):
            # Microsoft often mounts both fields before the active Next/Sign in
            # control. Wait for the action so we do not submit the wrong stage.
            await asyncio.sleep(0.25)
            continue

        if username_submitted and username_next_stage and not password_submitted:
            # The old username form is still transitioning. Its password input
            # may exist in the DOM, but submitting it while Next is active makes
            # Microsoft reject the verification flow.
            transition_error = await _visible_error(page)
            if transition_error:
                raise RuntimeError(
                    f"Identity-provider sign-in failed: {transition_error}"
                )
            await asyncio.sleep(0.25)
            continue

        if (
            username_next_stage
            and username_input is not None
            and not username_submitted
        ):
            await username_input.fill(username)
            await _submit_input(page, username_input)
            username_submitted = True
            _vprint("[*] Submitted the Microsoft username")
            await asyncio.sleep(1)
            continue

        if password_input is not None and not password_submitted:
            # Some Microsoft tenants render username and password together.
            # Fill both before the single submit instead of treating this as
            # Microsoft's traditional two-page form.
            if username_input is not None and not username_submitted:
                try:
                    username_editable = await username_input.is_editable(timeout=100)
                except Exception:
                    username_editable = True
                if username_editable:
                    await username_input.fill(username)
                    _vprint("[*] Filled the Microsoft username")
                username_submitted = True
            await asyncio.sleep(BROWSER_STEP_DELAY_SECONDS)
            password = await asyncio.to_thread(
                _ask_password, "Identity-provider password: "
            )
            await password_input.fill(password)
            password = ""
            await _submit_input(page, password_input)
            password_submitted = True
            password_submitted_at = time.monotonic()
            _vprint("[*] Submitted the Microsoft password")
            await asyncio.sleep(1)
            continue

        if username_input is not None and not username_submitted:
            await username_input.fill(username)
            await _submit_input(page, username_input)
            username_submitted = True
            _vprint("[*] Submitted the Microsoft username")
            await asyncio.sleep(1)
            continue

        otp_input = await _first_visible(page, OTP_SELECTORS)
        if otp_input is not None and not otp_submitted:
            otp = await asyncio.to_thread(
                input, "Authenticator code shown on your device: "
            )
            otp = otp.strip().replace(" ", "")
            if not otp:
                raise RuntimeError("An empty Authenticator code was entered")
            await otp_input.fill(otp)
            otp = ""
            await _submit_input(
                page,
                otp_input,
                (
                    "#idSubmit_SAOTCC_Continue",
                    *SUBMIT_SELECTORS,
                ),
            )
            otp_submitted = True
            _vprint("[*] Submitted the Microsoft verification code")
            await asyncio.sleep(1)
            continue

        error = await _visible_error(page)
        if error:
            if password_submitted and _looks_like_password_rejection(error):
                raise CredentialRejected(
                    f"Identity provider rejected the password: {error}"
                )
            raise RuntimeError(f"Identity-provider sign-in failed: {error}")

        if password_input is not None and password_submitted:
            if (
                password_enter_retried_at is None
                and time.monotonic() - password_submitted_at >= 2
            ):
                await password_input.press("Enter")
                password_enter_retried_at = time.monotonic()
                _vprint("[*] Retried Microsoft password submission with Enter")
                await asyncio.sleep(1)
                continue
            if (
                password_enter_retried_at is not None
                and time.monotonic() - password_enter_retried_at >= 15
            ):
                state = await _browser_page_state(page)
                raise RuntimeError(
                    "Microsoft kept the credential form open after both button "
                    f"and Enter submission ({state}). Verify the password "
                    "or retry once with --headed to inspect the page."
                )

        number_element = await _first_visible(page, NUMBER_MATCH_SELECTORS)
        number = None
        if number_element is not None:
            number_text = (await number_element.inner_text()).strip()
            number_match = re.search(r"\b\d{2,3}\b", number_text)
            number = number_match.group(0) if number_match else number_text

        page_text = ""
        try:
            page_text = await page.locator("body").inner_text(timeout=200)
        except Exception:
            pass
        if not number:
            number = _authenticator_number_from_text(page_text)
        if number:
            if number != displayed_number:
                print(f"[*] Enter this number in Microsoft Authenticator: {number}")
                displayed_number = number
                next_authenticator_reminder = time.monotonic() + 30
            await asyncio.sleep(0.5)
            continue

        if not printed_push_message and re.search(
            r"approve|notification|authenticator app", page_text, re.IGNORECASE
        ):
            print("[*] Approve the sign-in request in Microsoft Authenticator...")
            printed_push_message = True
            next_authenticator_reminder = time.monotonic() + 30

        if not authenticator_selected and await _choose_authenticator_method(page):
            authenticator_selected = True
            await asyncio.sleep(0.5)
            continue

        if (
            not account_picker_selected
            and username_input is None
            and password_input is None
            and otp_input is None
            and await _choose_microsoft_account(page, username)
        ):
            account_picker_selected = True
            _vprint("[*] Selected the Microsoft account sign-in path")
            await asyncio.sleep(0.5)
            continue

        if await _click_first_visible(page, ("#idBtn_Back",)):
            await asyncio.sleep(0.5)
            continue

        await asyncio.sleep(0.25)

    if not captured:
        raise TimeoutError(
            f"Timed out waiting for Microsoft sign-in after {timeout_seconds} seconds "
            f"(page: {page.url})"
        )


async def browser_saml_login(url, username, headed=False):
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise RuntimeError(
            "Missing Python dependency 'playwright' (install it with: pip install "
            "playwright && playwright install chromium)"
        ) from exc

    captured = {}
    async with async_playwright() as playwright:
        launch_options = {"headless": not headed}
        if proxy_url:
            launch_options["proxy"] = {"server": proxy_url}
        browser = await playwright.chromium.launch(**launch_options)
        context_options = {
            "user_agent": BROWSER_USER_AGENT,
            "ignore_https_errors": bool(proxy_url),
        }
        context = await browser.new_context(**context_options)
        page = await context.new_page()

        async def intercept_acs(route):
            request = route.request
            if request.method == "POST" and "SAMLResponse" in (request.post_data or ""):
                headers = {key.lower(): value for key, value in request.headers.items()}
                headers["user-agent"] = OPENCONNECT_USER_AGENT
                for generated_header in ("content-length", "host", "cookie"):
                    headers.pop(generated_header, None)
                captured.update(
                    url=request.url,
                    headers=headers,
                    post_data=request.post_data,
                )
                await route.abort()
            else:
                await route.continue_()

        await page.route("**/*", intercept_acs)
        try:
            try:
                await page.goto(url, wait_until="domcontentloaded")
            except Exception:
                if not captured:
                    raise
            _vprint("[*] Completing identity-provider sign-in in Chromium...")
            await _complete_microsoft_login(page, username, captured)

            form_payload = {
                key: values[0]
                for key, values in parse_qs(captured["post_data"]).items()
            }
            requests = _load_requests()
            response = await asyncio.to_thread(
                _gp_request,
                requests.post,
                captured["url"],
                headers=captured["headers"],
                data=form_payload,
                timeout=30,
            )
            response.raise_for_status()
            return response.text
        finally:
            await browser.close()


def csc_digest_md5(portal_csc_auth_cookie):
    template_path = Path(csc_template_path)
    try:
        template = template_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Unable to read CSC template {template_path}: {exc}") from exc

    replacements = {
        "{{PORTAL_CSC_AUTH_COOKIE}}": escape(portal_csc_auth_cookie),
        "{{USERNAME}}": escape(user_name),
        "{{CLIENT_OS}}": escape(quote_plus(csc_variables.get("CLIENT_OS", OS_VERSION_VALUE))),
        "{{HOST_ID}}": escape(host_id),
        "{{DEVICE_SERIAL_NUMBER}}": escape(device_serial),
    }
    missing = [placeholder for placeholder in replacements if placeholder not in template]
    if "{{CSC_DIGEST}}" not in template:
        missing.append("{{CSC_DIGEST}}")
    if missing:
        raise RuntimeError(
            f"CSC template {template_path} is missing: {', '.join(missing)}"
        )

    report = template
    for placeholder, value in replacements.items():
        report = report.replace(placeholder, value)
    for name, value in csc_variables.items():
        report = report.replace(f"{{{{{name}}}}}", escape(value))
    unresolved = sorted(set(re.findall(r"{{([A-Za-z_][A-Za-z0-9_]*)}}", report)))
    unresolved = [name for name in unresolved if name != "CSC_DIGEST"]
    if unresolved:
        raise RuntimeError(
            "CSC template variables need values: " + ", ".join(unresolved)
        )
    digest_source = report.replace("{{CSC_DIGEST}}", CSC_DIGEST_PLACEHOLDER)
    digest = hashlib.md5(digest_source.encode("utf-8")).hexdigest()
    return report.replace("{{CSC_DIGEST}}", digest), digest


def _getconfig_params(prelogin_cookie, password="", non_saml=False):
    # The field set and values of stock OpenConnect's portal getconfig request.
    params = {
        "jnlpReady": "jnlpReady",
        "ok": "Login",
        "direct": "yes",
        "clientVer": CLIENT_VERSION,
        "prot": "https:",
        "internal": "no",
        "ipv6-support": "yes",
        "clientos": CLIENT_OS,
        "os-version": OS_VERSION_VALUE,
        "server": urlparse(PORTAL).netloc,
        "computer": hostname,
        "inputStr": "",
        "user": user_name or "",
    }
    if non_saml:
        params["passwd"] = password
    else:
        params["prelogin-cookie"] = prelogin_cookie
    # The one addition to OpenConnect's set: without it a portal does not say
    # that it requires a client-side check, which is what this tool reports.
    params["csc-support"] = "yes"
    # OpenConnect sends neither of these. They are sent only on the CSC run,
    # where --host-id and --serial are required.
    if host_id:
        params["host-id"] = host_id
    if device_serial:
        params["serialno"] = device_serial
    return params


def get_config(prelogin_cookie, password="", non_saml=False):
    global last_generated_hip_template, last_config_xml, csc_state
    requests = _load_requests()
    headers = {
        "User-Agent": OPENCONNECT_USER_AGENT,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    response = _gp_request(
        requests.post,
        f"{PORTAL}/global-protect/getconfig.esp",
        headers=headers,
        data=_getconfig_params(prelogin_cookie, password, non_saml),
        timeout=30,
    )
    if non_saml and response.status_code in {401, 403}:
        raise CredentialRejected(
            f"GlobalProtect rejected the username/password credentials "
            f"(HTTP {response.status_code})"
        )
    response.raise_for_status()
    _save_response_artifacts(response.text, "getconfig", output_dir)

    portal_csc_auth_cookie = _extract_text(response.text, "portal-csc-auth-cookie")
    final_response_text = response.text
    if portal_csc_auth_cookie:
        if not csc_template_path:
            config_criteria = _extract_xml_fragment(response.text, "config-criteria")
            if not config_criteria:
                raise ReviewRequired(
                    "Portal requires CSC data, but its config-criteria XML could not "
                    "be extracted. Run again with --raw-save and review "
                    "raw_responses/getconfig.xml."
                )
            generated_template = generate_csc_template(
                config_criteria, CSC_TEMPLATE_DIR
            )
            raise ReviewRequired(
                "this portal requires a client-side check (CSC) before it returns "
                "its full configuration.\n"
                f"    Template written to: {generated_template}\n"
                "    Fill in its value placeholders with the real endpoint's values, "
                "then run again with:\n"
                f"      --csc-template {generated_template} --host-id HOST_ID --serial SERIAL"
            )
        _vprint(
            "[*] Portal CSC check requested; building the CSC report from the template..."
        )
        csc_data, csc_digest = csc_digest_md5(portal_csc_auth_cookie)
        generated_path = _versioned_output_path(
            Path(output_dir) / "generated", "csc-report.xml"
        )
        _write_private_file(generated_path, csc_data)
        print(f"[*] Generated CSC report saved to {generated_path}")

        csc_response = _gp_request(
            requests.post,
            f"{PORTAL}/global-protect/getconfig_csc.esp",
            headers=headers,
            data={
                "user": user_name,
                "clientVer": CLIENT_VERSION,
                "clientos": CLIENT_OS,
                "os-version": OS_VERSION_VALUE,
                "hostid": host_id,
                "serialno": device_serial,
                "portal-cc-auth-cookie": portal_csc_auth_cookie,
                "config-digest": "",
                "csc-digest": csc_digest,
                "csc-data": csc_data,
            },
            timeout=30,
        )
        csc_response.raise_for_status()
        final_response_text = csc_response.text
        csc_state = f"required; submitted from {csc_template_path}"
        _save_response_artifacts(final_response_text, "getconfig_csc", output_dir)
    else:
        _vprint(
            "[*] No portal CSC cookie was returned; no additional CSC check is needed."
        )

    hip_collection = _extract_xml_fragment(final_response_text, "hip-collection")
    if not hip_collection:
        hip_collection = _extract_xml_fragment(response.text, "hip-collection")
    if hip_collection:
        last_generated_hip_template = generate_hip_template(
            hip_collection, HIP_TEMPLATE_DIR
        )

    user_auth_cookie = _extract_text(final_response_text, "portal-userauthcookie")
    if not user_auth_cookie:
        user_auth_cookie = _extract_text(response.text, "portal-userauthcookie")
    if user_auth_cookie == "empty":  # the portal's value when it issues none
        user_auth_cookie = None
    last_config_xml = final_response_text
    if not user_auth_cookie and "<gateways" in final_response_text:
        # Signed in and configured, but this portal issues no auth cookie.
        return None
    if not user_auth_cookie:
        message = (
            _extract_text(final_response_text, "msg")
            or _extract_text(final_response_text, "newmsg")
        )
        detail = f": {message}" if message else ""
        if non_saml:
            raise CredentialRejected(
                f"GlobalProtect rejected the username/password credentials{detail}"
            )
        raise RuntimeError(
            f"GlobalProtect response did not contain a user auth cookie{detail}"
        )
    cookie_path = Path(output_dir) / "userauthcookie.dat"
    _write_private_file(cookie_path, user_auth_cookie)
    _vprint(f"[+] GlobalProtect user auth cookie saved to {cookie_path}")
    return cookie_path


def _describe_authentication(discovery):
    """Say what the portal asks for, before asking the operator for it."""
    method = discovery["method"]
    if method == "password":
        print("[*] Authentication: username and password.")
        banner = _extract_text(discovery.get("response", ""), "authentication-message")
        if banner:
            print(f"    Portal banner: {banner}")
        return
    if method != "saml":
        return
    idp_url = discovery["idp_url"]
    idp_host = urlparse(idp_url).hostname or idp_url
    binding = discovery["saml_start"].get("portal_method", "")
    tenant = re.search(r"/([0-9a-fA-F-]{36})(?:/|$)", urlparse(idp_url).path)
    line = f"[*] Authentication: SAML ({binding}) via {idp_host}"
    if discovery["microsoft_idp"] and tenant:
        line += f", Entra tenant {tenant.group(1)}"
    print(line + ".")


def _config_gateways(config_xml):
    """External gateways listed in a portal configuration: [(address, description)]."""
    try:
        root = ET.fromstring(config_xml)
    except ET.ParseError:
        return []
    gateways = []
    for external in root.iter():
        if _xml_local_name(external.tag) != "external":
            continue
        for gateway_list in external:
            if _xml_local_name(gateway_list.tag) != "list":
                continue
            for entry in gateway_list:
                name = entry.get("name")
                if not name:
                    continue
                description = ""
                for child in entry:
                    if _xml_local_name(child.tag) == "description":
                        description = (child.text or "").strip()
                if (name, description) not in gateways:
                    gateways.append((name, description))
    return gateways


def _hip_categories(config_xml):
    fragment = _extract_xml_fragment(config_xml, "hip-collection")
    if not fragment:
        return None
    try:
        collection = ET.fromstring(fragment)
    except ET.ParseError:
        return []
    categories = []
    for element in collection.iter():
        if _xml_local_name(element.tag) != "category":
            continue
        for member in element:
            name = (member.text or "").strip()
            if _xml_local_name(member.tag) == "member" and name and name not in categories:
                categories.append(name)
    return categories


def _print_summary(cookie_path):
    print()
    print("Result")
    print(f"  Signed in as : {user_name}")
    gateways = _config_gateways(last_config_xml or "")
    if gateways:
        for index, (address, description) in enumerate(gateways):
            label = "  Gateways     :" if index == 0 else "                "
            print(f"{label} {address}" + (f" ({description})" if description else ""))
    else:
        print("  Gateways     : none listed in the configuration")
    print(f"  CSC          : {csc_state}")
    categories = _hip_categories(last_config_xml or "")
    if categories is None:
        print("  HIP          : not collected by this portal configuration")
    else:
        print(f"  HIP          : collected - {', '.join(categories) or 'no categories listed'}")
        if last_generated_hip_template:
            print(f"  HIP template : {last_generated_hip_template}")
    print(f"  Saved in     : {Path(output_dir).resolve()}")
    if cookie_path:
        print(f"  Auth cookie  : {cookie_path} (a live credential)")
    else:
        print("  Auth cookie  : none issued by this portal")


def _ask_username(required=True):
    global user_name
    if not user_name:
        prompt = "Username: " if required else "Username (Enter to skip): "
        try:
            user_name = input(prompt).strip()
        except EOFError:
            user_name = ""
    if required and not user_name:
        raise RuntimeError("A username is required (or pass --username)")
    return user_name


def authenticate(args, discovery=None):
    global user_name
    discovery = discovery or discover_portal_authentication()
    method = discovery["method"]
    _describe_authentication(discovery)

    if method == "certificate":
        if client_cert:
            raise RuntimeError(
                "The portal still requires a client certificate after one was supplied: "
                + discovery.get("message", "certificate rejected")
            )
        raise RuntimeError(
            "The portal requires a client certificate. Pass --client-pfx or "
            "--client-cert/--client-key."
        )

    if method == "password":
        if args.cookie_file:
            raise RuntimeError(
                "Cookie authentication was requested, but the portal advertises "
                "username/password authentication"
            )
        _ask_username()
        return get_config("", password=_ask_password("Password: "), non_saml=True)

    if method != "saml":
        raise RuntimeError(f"Unsupported portal authentication method: {method}")
    login_url = discovery["login_url"]
    saml_start = discovery["saml_start"]
    idp_url = discovery["idp_url"]
    microsoft_idp = discovery["microsoft_idp"]

    if args.cookie_file:
        _vprint("[*] Authenticating with cookies using requests only...")
        saml_response = requests_saml_login(
            saml_start, idp_url, _parse_cookie_file(args.cookie_file)
        )
    else:
        if proxy_url:
            print("    Sign-in runs in Chromium through the proxy.")
        else:
            print("    Sign-in runs in Chromium; the username and password are asked here.")
            if microsoft_idp:
                print(
                    "    For a PRT handoff instead, start saml_bridge and add "
                    "--proxy 127.0.0.1:8888."
                )
        # Through the proxy the sign-in may need no typed username at all.
        _ask_username(required=not proxy_url)
        saml_response = asyncio.run(
            browser_saml_login(login_url, user_name or "", headed=args.headed)
        )

    _save_response_artifacts(saml_response, "saml_acs", output_dir)
    prelogin_cookie = _extract_text(saml_response, "prelogin-cookie")
    if not prelogin_cookie:
        raise RuntimeError(
            "SAML was accepted, but the GlobalProtect response did not contain "
            "a prelogin cookie"
        )
    # As a real client does, use the username the portal derived from the
    # assertion, which can differ from what was typed at the IdP.
    saml_username = _extract_text(saml_response, "saml-username")
    if saml_username:
        user_name = saml_username
    if not user_name:
        raise RuntimeError(
            "The portal accepted SAML but named no user; pass --username"
        )
    _vprint("[+] SAML accepted; requesting GlobalProtect configuration...")
    return get_config(prelogin_cookie)


def parse_args():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("portal", help="GlobalProtect portal hostname or URL")
    parser.add_argument("-u", "--username", help="username (asked for when needed)")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="show each step in detail"
    )
    parser.add_argument(
        "--raw-save", action="store_true", help="also keep the full portal/IdP responses"
    )

    sign_in = parser.add_argument_group(
        "sign-in (all optional; the tool asks for what the portal needs)"
    )
    certificate = sign_in.add_mutually_exclusive_group()
    certificate.add_argument(
        "--client-pfx", type=Path, help="client certificate as PFX/PKCS#12"
    )
    certificate.add_argument(
        "--client-cert", type=Path, help="client certificate as PEM (may include the key)"
    )
    sign_in.add_argument(
        "--client-key", type=Path, help="separate PEM private key for --client-cert"
    )
    sign_in.add_argument(
        "--ca-cert", type=Path, help="CA bundle to verify the portal's own certificate"
    )
    sign_in.add_argument(
        "--proxy",
        dest="proxy_url",
        help="HTTP(S) proxy for portal, IdP and browser, e.g. saml_bridge at "
        "127.0.0.1:8888; TLS verification is disabled while set",
    )
    sign_in.add_argument(
        "--cookie-file",
        type=Path,
        help="SAML with existing IdP cookies (comma/newline-separated name=value), no browser",
    )
    sign_in.add_argument(
        "--headed", action="store_true", help="show the Chromium window during SAML sign-in"
    )

    csc = parser.add_argument_group("client-side check (only if the portal requires one)")
    csc.add_argument(
        "--csc-template", type=Path,
        help="reviewed CSC template to submit (generated on the first run)",
    )
    csc.add_argument(
        "--csc-var", action="append", metavar="NAME=VALUE",
        help="value for a {{NAME}} placeholder in the template; may be repeated",
    )
    csc.add_argument("--host-id", help="endpoint host ID (required with --csc-template)")
    csc.add_argument(
        "--serial", dest="device_serial",
        help="endpoint serial number (required with --csc-template)",
    )

    args = parser.parse_args()
    try:
        args.portal = _normalize_gp_server_url(args.portal, "portal")
        args.csc_variables = _parse_csc_variables(args.csc_var)
    except RuntimeError as exc:
        parser.error(str(exc))
    if args.proxy_url:
        if "://" not in args.proxy_url:
            args.proxy_url = "http://" + args.proxy_url
        parsed_proxy = urlparse(args.proxy_url)
        if not parsed_proxy.scheme or not parsed_proxy.hostname:
            parser.error("--proxy must be a proxy URL such as http://127.0.0.1:8080")
        try:
            parsed_proxy.port
        except ValueError as exc:
            parser.error(f"invalid --proxy port: {exc}")
    if args.cookie_file and args.headed:
        parser.error("--headed applies only to browser sign-in")
    if args.client_key and not args.client_cert:
        parser.error("--client-key requires --client-cert")
    if args.csc_template and not (args.host_id and args.device_serial):
        parser.error("--csc-template needs --host-id and --serial (the endpoint it describes)")
    for path_argument, label in (
        (args.cookie_file, "--cookie-file"),
        (args.client_pfx, "--client-pfx"),
        (args.client_cert, "--client-cert"),
        (args.client_key, "--client-key"),
        (args.ca_cert, "--ca-cert"),
        (args.csc_template, "--csc-template"),
    ):
        if path_argument and not path_argument.is_file():
            parser.error(f"{label} file does not exist: {path_argument}")

    return args


def main():
    global user_name, host_id, device_serial, hostname
    global csc_template_path, output_dir
    global client_cert, ca_cert, proxy_url, save_raw_responses
    global verbose_mode, csc_variables
    global PORTAL

    _configure_console_output()
    signal.signal(signal.SIGTERM, _handle_termination_signal)
    args = parse_args()
    user_name = args.username
    host_id = args.host_id
    device_serial = args.device_serial
    hostname = socket.gethostname() or "localhost"
    csc_template_path = args.csc_template
    output_dir = OUTPUT_DIR
    ca_cert = args.ca_cert
    proxy_url = args.proxy_url
    save_raw_responses = args.raw_save
    verbose_mode = args.verbose
    csc_variables = args.csc_variables
    PORTAL = args.portal

    print(f"[*] Portal: {PORTAL}")
    _vprint(
        f'[*] Identifying as: User-Agent "{OPENCONNECT_USER_AGENT}", clientos {CLIENT_OS}, '
        f"os-version {OS_VERSION_VALUE}, computer {hostname}"
    )
    if proxy_url:
        parsed_proxy = urlparse(proxy_url)
        proxy_display = f"{parsed_proxy.scheme}://{parsed_proxy.hostname}"
        if parsed_proxy.port:
            proxy_display += f":{parsed_proxy.port}"
        print(
            f"[!] Proxy enabled through {proxy_display}; Python request and browser "
            "TLS verification is disabled."
        )

    pending_discovery = None
    client_cert = None
    if not args.client_pfx and not args.client_cert:
        pending_discovery = discover_portal_authentication()
        if pending_discovery["method"] == "certificate":
            print("[*] Authentication: client certificate required.")
            if not sys.stdin.isatty():
                raise RuntimeError(
                    "Pass the certificate with --client-pfx FILE, or "
                    "--client-cert FILE [--client-key FILE]."
                )
            print("    (next time: --client-pfx FILE, or --client-cert FILE [--client-key FILE])")
            _prompt_for_client_certificate(args)
            pending_discovery = None

    with _prepared_client_certificate(args) as prepared_certificate:
        client_cert = prepared_certificate
        cookie_path = authenticate(args, discovery=pending_discovery)
        _print_summary(cookie_path)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] Cancelled")
        raise SystemExit(130)
    except ReviewRequired as exc:
        print(f"[!] Review required: {exc}")
        raise SystemExit(2)
    except Exception as exc:
        print(f"[-] Error: {exc}")
        raise SystemExit(1)
