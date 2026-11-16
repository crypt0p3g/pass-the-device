#!/usr/bin/env python3
"""Netskope Scout - read-only tenant reconnaissance.

Given a Netskope tenant name (and optionally a user's email address), Scout
discovers the tenant OrgKey from the public nsauth SAML redirect and then reads
the tenant's addon configuration endpoints: steering domains, exceptions,
pinned (SSL-pinned) apps, bypass/overlapping domains, tunnel policy, the PAC,
managed device-compliance checks, and client update links.

Scout only reads. Apart from the one unauthenticated POST that starts the
public nsauth SAML flow (how the OrgKey is discovered), every request is a GET.
Use it only against tenants you own or are permitted to test.
"""

import argparse
import base64
import json
import re
import sys
import time
from urllib.parse import quote

import requests

NS_AGENT = "Windows NT 11.0 x64;Netskope ST Agent 132.0.16.2541"
OS_LIST = ("win", "mac", "ios", "android")

DEFAULT_CLIENT_DOWNLOAD_LINKS = {
    "win": "https://download.goskope.com/dlr/win/get",
    "mac": "https://download.goskope.com/dlr/mac/get",
}

# Read-only addon endpoints. {tenant}/{orgkey}/{userkey}/{email}/{os} are filled in.
ADDON_APIS = {
    "get_userkey":         "https://addon-{tenant}.goskope.com/config/user/getbrandingbyemail?orgkey={orgkey}&email={email}",
    "get_version":         "https://addon-{tenant}.goskope.com/config/org/version?orgkey={orgkey}",
    "get_config":          "https://addon-{tenant}.goskope.com/v2/config/org/clientconfig?orgkey={orgkey}&hashkey={userkey}",
    "get_domains":         "https://addon-{tenant}.goskope.com/v1/steering/domains?orgkey={orgkey}&userkey={userkey}&os=win",
    "get_exceptions":      "https://addon-{tenant}.goskope.com/v1/steering/exceptions?orgkey={orgkey}&userkey={userkey}&os=win",
    "get_pinned_apps":     "https://addon-{tenant}.goskope.com/v1/steering/pinnedapps?orgkey={orgkey}&userkey={userkey}&os=win",
    "get_managed_checks":  "https://addon-{tenant}.goskope.com/v2/config/org/getmanagedchecks?orgkey={orgkey}&os={os}",
    "get_categories":      "https://addon-{tenant}.goskope.com/steering/categories?orgkey={orgkey}&userkey={userkey}&os=win",
    "get_overdomain_list": "https://addon-{tenant}.goskope.com/config/getoverlappingdomainlist?orgkey={orgkey}",
    "get_tunnel_policy":   "https://addon-{tenant}.goskope.com/config/org/gettunnelpolicy?orgkey={orgkey}&os=win",
    "get_pac":             "https://addon-{tenant}.goskope.com/config/user/pac?orgkey={orgkey}",
    "get_update":          "https://addon-{tenant}.goskope.com/v2/checkupdate?orgkey={orgkey}&os={os}",
}


class Scout:
    def __init__(self, tenant, email, delay, timeout, verbose):
        # The tenant becomes part of a hostname, so refuse anything that could
        # redirect the requests somewhere else.
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", tenant or ""):
            raise SystemExit(
                f'[-] Invalid tenant name "{tenant}": expected the <x> in '
                "addon-<x>.goskope.com (letters, digits, hyphens)."
            )
        self.tenant = tenant
        self.email = email
        self.delay = delay
        self.timeout = timeout
        self.verbose = verbose
        self.orgkey = None
        self.userkey = "0"
        self.secure_enrollment = None  # True/False/None(unknown)
        self.results = {}
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": NS_AGENT})

    # -- transport ---------------------------------------------------------
    def _url(self, name, **extra):
        return ADDON_APIS[name].format(
            tenant=self.tenant,
            orgkey=quote(self.orgkey or "", safe=""),
            userkey=quote(str(self.userkey), safe=""),
            email=quote(self.email or "", safe="@"),
            os=extra.get("os", "win"),
        ) + extra.get("suffix", "")

    def _get(self, url):
        time.sleep(self.delay)
        try:
            resp = self.session.get(url, timeout=self.timeout)
        except requests.exceptions.RequestException as exc:
            if self.verbose:
                # Not str(exc): it repeats the URL, whose query carries the keys.
                path = url.split("?", 1)[0]
                print(f"[-] request failed: {path} ({exc.__class__.__name__})", file=sys.stderr)
            return None
        try:
            return resp.json()
        except ValueError:
            return resp.text

    # -- discovery ---------------------------------------------------------
    def fetch_orgkey(self):
        """OrgKey leaks from the nsauth SAMLRequest ACS URL. Anonymous."""
        url = f"https://nsauth-{self.tenant}.goskope.com/nsauth/client/authenticate"
        try:
            resp = self.session.post(
                url,
                data={"TenantName": self.tenant, "UTCEpoch": str(time.time())},
                timeout=self.timeout,
            )
        except requests.exceptions.RequestException as exc:
            if self.verbose:
                print(f"[-] request failed: {url} ({exc.__class__.__name__})", file=sys.stderr)
            return None

        if "ERR_IDP_CONFIG_NOT_FOUND" in resp.text:
            return None

        match = re.search(r'SAMLRequest" value="([^"]*)"', resp.text)
        if not match:
            return None
        try:
            decoded = base64.b64decode(match.group(1))
        except Exception:
            return None
        acs = re.search(rb"http-post/([^/]*)/acs", decoded)
        if not acs:
            return None
        return acs.group(1).decode("ascii", "replace")

    def prepare(self):
        self.orgkey = self.fetch_orgkey()
        if not self.orgkey:
            raise SystemExit(
                f'[-] Could not resolve OrgKey for "{self.tenant}". '
                "Tenant does not exist, is firewalled, or has no IdP config."
            )
        self.results["tenant"] = self.tenant
        self.results["orgkey"] = self.orgkey
        self.findings.append(f"OrgKey discovered anonymously: {self.orgkey}")

    # -- userkey oracle ----------------------------------------------------
    def check_secure_enrollment(self):
        """getbrandingbyemail returns a UserKey only when Secure Enrollment is
        OFF. Presence/absence is the signal; the UserKey itself is enrollment
        material and is not printed."""
        if not self.email:
            return
        branding = self._get(self._url("get_userkey"))
        if not isinstance(branding, dict):
            return
        if branding.get("status") == "error":
            msg = str(branding.get("message") or "")
            if "Unable to find user" in msg:
                self.findings.append(f"User oracle: '{self.email}' NOT found in tenant")
            else:
                self.findings.append(
                    f"Secure Enrollment: unknown (the tenant answered: {msg or 'error'})"
                )
            return
        if "UserKey" in branding:
            self.userkey = branding["UserKey"]
            self.secure_enrollment = False
            self.findings.append(
                "Secure Enrollment: OFF (UserKey issued for this email; value masked)"
            )
            # keep branding but drop the key material from reported output
            redacted = dict(branding)
            redacted["UserKey"] = "(masked)"
            self.results["branding"] = redacted
        else:
            self.secure_enrollment = True
            self.findings.append("Secure Enrollment: appears ON (no UserKey issued)")

    # -- read-only enumeration --------------------------------------------
    def enumerate(self):
        self.results["version"] = self._get(self._url("get_version"))

        tenant_cfg = self._get(self._url("get_config", suffix="&tenantconfig=1"))
        self.results["tenant_config"] = tenant_cfg
        if isinstance(tenant_cfg, dict):
            npa = tenant_cfg.get("npa") or {}
            if npa.get("tenant"):
                self.findings.append(f"NPA tenant host: {npa['tenant']}")

        self.results["user_config"] = self._get(self._url("get_config", suffix="&userconfig=1"))

        self.results["steering_domains"] = self._get(self._url("get_domains"))

        exceptions = self._get(self._url("get_exceptions"))
        self.results["steering_exceptions"] = exceptions
        n = _count(exceptions)
        if n:
            self.findings.append(f"Steering exceptions present: {n} entries skip inspection")

        pinned = self._get(self._url("get_pinned_apps"))
        self.results["pinned_apps"] = pinned
        if _has_wildcard(pinned):
            self.findings.append("Pinned apps include a wildcard (*) entry")

        self.results["categories"] = self._get(self._url("get_categories"))
        self.results["overlapping_domains"] = self._get(self._url("get_overdomain_list"))
        self.results["tunnel_policy"] = self._get(self._url("get_tunnel_policy"))
        self.results["pac"] = self._get(self._url("get_pac"))

        checks = {}
        for os_name in OS_LIST:
            result = self._get(self._url("get_managed_checks", os=os_name))
            if isinstance(result, dict) and result.get("latest_modified_time"):
                checks[os_name] = result
        if checks:
            self.results["managed_checks"] = checks
            self.findings.append(
                "Managed device-compliance checks defined for: " + ", ".join(checks)
            )

        updates = {}
        for os_name in ("win", "mac"):
            updates[os_name] = self._get(self._url("get_update", os=os_name))
        self.results["client_updates"] = updates

    def run(self):
        self.prepare()
        self.check_secure_enrollment()
        self.enumerate()
        self.results["secure_enrollment"] = self.secure_enrollment
        self.results["findings"] = list(self.findings)


def _count(value):
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        for key in ("domains", "exceptions", "list", "data"):
            if isinstance(value.get(key), list):
                return len(value[key])
    return 0


def _has_wildcard(value):
    return "*" in json.dumps(value) if value else False


def print_report(scout):
    print("=" * 70)
    print(f"Netskope Scout - {scout.tenant}")
    print("=" * 70)
    print(f"OrgKey: {scout.orgkey}")
    if scout.secure_enrollment is False:
        print("Secure Enrollment: OFF")
    elif scout.secure_enrollment is True:
        print("Secure Enrollment: appears ON")
    print()
    print("Findings:")
    for item in scout.findings:
        print(f"  [+] {item}")
    print()
    for name, value in scout.results.items():
        if name in ("tenant", "orgkey", "secure_enrollment", "findings"):
            continue
        print("-" * 70)
        print(f"[{name}]")
        if isinstance(value, (dict, list)):
            text, limit = json.dumps(value, indent=2), 8000
        else:
            text, limit = str(value), 4000
        print(text[:limit])
        if len(text) > limit:
            print("... (truncated; --json has the full section)")
    print("-" * 70)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p):
        p.add_argument("tenant", help="tenant name (the <x> in addon-<x>.goskope.com)")
        p.add_argument("--delay", type=float, default=1.0, help="seconds between requests")
        p.add_argument("--timeout", type=float, default=30, help="per-request timeout in seconds")
        p.add_argument("--json", metavar="PATH", help="write full results as JSON (- for stdout)")
        p.add_argument("--verbose", action="store_true", help="report failed requests on stderr")

    org = sub.add_parser("orgkey-recon", help="OrgKey discovery + tenant-wide read-only enum")
    add_common(org)

    user = sub.add_parser("userkey-recon", help="also probe Secure Enrollment for an email")
    add_common(user)
    user.add_argument("email", help="user email address to test for enrollment")

    sub.add_parser("download-client", help="print default client download links")

    args = parser.parse_args()

    if args.command == "download-client":
        for os_name, link in DEFAULT_CLIENT_DOWNLOAD_LINKS.items():
            print(f"{os_name}: {link}")
        return 0

    email = getattr(args, "email", None)
    scout = Scout(args.tenant, email=email, delay=args.delay, timeout=args.timeout, verbose=args.verbose)
    scout.run()

    if args.json:
        payload = json.dumps(scout.results, indent=2)
        if args.json == "-":
            print(payload)
        else:
            with open(args.json, "w", encoding="utf-8") as handle:
                handle.write(payload)
            print(f"[+] wrote {args.json}", file=sys.stderr)
    else:
        print_report(scout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
