# GlobalProtect Recon (`gp_recon.py`)

**What does this GlobalProtect portal ask of a client?** Give it the portal:

```sh
./gp_recon.py portal.example.com
```

It asks the portal how it authenticates, tells you what it needs, signs in,
fetches the portal configuration, and reports:

- the external gateways the portal hands out;
- the HIP categories the portal collects (with a review template);
- whether a client-side check (CSC) is required (with a review template).

**It never establishes a VPN connection and never submits a HIP report.**

> **Authorized use only.** This signs in to a real portal as a real user. Use
> it only against portals and accounts you own or have written permission to
> assess.

## Install

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m playwright install chromium      # only needed for SAML portals
```

`requests` is always needed, `playwright` for SAML sign-in in a browser, and
`cryptography` for PFX or encrypted PEM client certificates.

## How it identifies itself

Requests to the portal are the ones stock OpenConnect sends
(`openconnect --protocol=gp --os=win`), so defenders can find this tool in
portal logs the same way they find OpenConnect:

| Field | Value |
| --- | --- |
| `User-Agent` | `PAN GlobalProtect` |
| `clientVer` | `4100` |
| `clientos` / `os-version` | `Windows` / `win` |
| `computer` | this machine's hostname |

These values are fixed; there are no options to change them. There is one
addition to OpenConnect's set: `csc-support=yes`, without which a portal does
not reveal that it requires a client-side check. A host ID and serial number
are sent only on a CSC run. The Chromium window used for SAML has an ordinary
browser User-Agent.

## What happens

```text
$ ./gp_recon.py portal.example.com
[*] Portal: https://portal.example.com
[*] Authentication: SAML (REDIRECT) via login.microsoftonline.com, Entra tenant 1111...
    Sign-in runs in Chromium; the username and password are asked here.
    For a PRT handoff instead, start saml_bridge and add --proxy 127.0.0.1:8888.
Username: user@example.com
Identity-provider password:

Result
  Signed in as : user@example.com
  Gateways     : gw1.example.com (Tokyo)
                 gw2.example.com (Osaka)
  CSC          : not required
  HIP          : collected - host-info, anti-malware, disk-encryption
  HIP template : /path/to/gp_recon/hip_templates/required_hip.xml
  Saved in     : /path/to/gp_recon_output
  Auth cookie  : gp_recon_output/userauthcookie.dat (a live credential)
```

What it asks for depends on what the portal says:

| Portal says | The tool |
| --- | --- |
| Username and password | asks for both (`--username` skips the first prompt) |
| Client certificate required | asks for the certificate path, or take `--client-pfx FILE` / `--client-cert FILE [--client-key FILE]` |
| SAML | asks for the username, then signs in through headless Chromium, asking for the password and relaying authenticator codes or number-matching prompts |

Passwords are always asked with a hidden prompt and held in memory only; there
is no option to pass one on the command line.

### SAML options

- **Browser (default).** Add `--headed` to watch the Chromium window. The
  sign-in automation is written for Microsoft pages; other IdPs work when their
  form uses common field names. It waits up to 300 seconds for the sign-in and
  keeps no browser session on disk.
- **PRT handoff.** Start the separate `saml_bridge` tool and route the sign-in
  through it: `--proxy 127.0.0.1:8888`. No username is needed. TLS
  verification is disabled for the portal, IdP and browser while a proxy is
  set (`--ca-cert` is then ignored), and the tool says so.
- **Existing IdP cookies.** `--cookie-file cookies.txt` (comma- or
  newline-separated `name=value`) signs in without a browser.

### Client certificate

```sh
./gp_recon.py portal.example.com --client-pfx client.pfx
./gp_recon.py portal.example.com --client-cert client.pem --client-key client.key
./gp_recon.py portal.example.com --ca-cert company-ca.pem      # private CA on the portal
```

A PFX or key password is asked for if needed. Requests to the IdP never carry
the client certificate. It is sent to the portal and to the SAML
assertion-consumer URL the IdP posts back to.

## When the portal requires a client-side check (CSC)

A run without `--csc-template` stops with exit status 2 and writes a template
of what the portal checks:

```text
[!] Review required: this portal requires a client-side check (CSC) before it returns its full configuration.
    Template written to: /path/to/gp_recon/csc_templates/required_csc.xml
    Fill in its value placeholders with the real endpoint's values, then run again with:
      --csc-template /path/to/gp_recon/csc_templates/required_csc.xml --host-id HOST_ID --serial SERIAL
```

Fill in the device-specific placeholders, either in the file or with
`--csc-var NAME=VALUE`, and leave the runtime placeholders
(`{{PORTAL_CSC_AUTH_COOKIE}}`, `{{USERNAME}}`, `{{CLIENT_OS}}`, `{{HOST_ID}}`,
`{{DEVICE_SERIAL_NUMBER}}`, `{{CSC_DIGEST}}`) as they are. Then:

```sh
./gp_recon.py portal.example.com \
  --csc-template csc_templates/required_csc.xml \
  --host-id 00000000-0000-0000-0000-000000000000 --serial EXAMPLE-SERIAL \
  --csc-var 'REG_HKEY_LOCAL_MACHINE_SYSTEM_HARDWARECONFIG_LASTCONFIG_VALUE={actual-value}'
```

This run renders the template, computes its digest, submits it to
`getconfig_csc.esp`, and reports the configuration the portal then returns.
`{{CLIENT_OS}}` is filled with `win`; if the portal compares it, give the
endpoint's real OS string with `--csc-var 'CLIENT_OS=Microsoft Windows 11 Enterprise , 64-bit'`
(it is URL-encoded when inserted). `--csc-var` cannot override the other
runtime placeholders.

## HIP

When the configuration contains a HIP collection policy, the categories are
listed in the result and a skeleton HIP report is written to
`hip_templates/required_hip.xml` next to the script. It is a review artifact showing what a client
would be asked to report. `gp_recon.py` does not fill it in or submit it.

## Output files

```text
gp_recon_output/
├── userauthcookie.dat          portal auth cookie, if issued: treat it like a password
├── extracted/                  config-criteria.xml, hip-collection.xml
├── generated/csc-report.xml    the CSC report that was submitted
└── raw_responses/              only with --raw-save
```

`gp_recon_output/` is created in the directory you run the tool from.
Templates go to `csc_templates/` and `hip_templates/` next to the script.
Templates and extracted, generated and raw files are never overwritten; later
ones get a timestamp. `userauthcookie.dat` is replaced on every run. Files are
written with private permissions, and all of them may contain authentication
or endpoint data.

## Options

| Option | Purpose |
| --- | --- |
| `-u`, `--username` | skip the username prompt |
| `--client-pfx`, `--client-cert`, `--client-key` | client certificate |
| `--ca-cert` | CA bundle for a portal with a private CA |
| `--proxy` | route everything through a proxy such as `saml_bridge` |
| `--cookie-file` | SAML with existing IdP cookies |
| `--headed` | show the Chromium window |
| `--csc-template`, `--csc-var`, `--host-id`, `--serial` | the CSC run |
| `--raw-save` | keep full responses |
| `-v`, `--verbose` | show each step |

## Exit statuses

- `0`: signed in and reported the configuration;
- `1`: configuration, authentication, or request failure;
- `2`: a CSC template needs your review before continuing, or a usage error;
- `130`: cancelled with Ctrl+C.

## Limits

- The OpenConnect-style requests have been checked end to end against a
  simulated portal, and the prelogin step against a live Prisma Access portal.
  A full sign-in against a live portal with these defaults has not been run.
- A portal may hand an OpenConnect-style client less than it hands a full
  GlobalProtect client, or refuse it.
