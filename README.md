# Pass-the-Device

Tools and detections from the CODE BLUE 2026 talk *Pass-the-Device: Transplanting SASE/VPN Trust After Endpoint Compromise*.
Red teams get recon tools to test whether remote-access trust can leave the device; blue teams get
Sigma and KQL to see it when it does ([`detections/`](detections/)).
The companion DPAPI toolkit lives in its own repository: [crypt0p3g/dpapi-toolkit](https://github.com/crypt0p3g/dpapi-toolkit).

## Slides

- English: [`slides/pass-the-device-en.pdf`](slides/pass-the-device-en.pdf)
- 日本語: [`slides/pass-the-device-ja.pdf`](slides/pass-the-device-ja.pdf)

50 talk slides and a 24-page reference appendix (A01-A24), with bookmarks.

## Remote-access trust-boundary tools

A small collection of **reconnaissance-focused** tools for inspecting the trust
boundary of VPN / SASE remote-access products. They were written for authorized
security assessments and a conference talk on remote-access device trust.

> **Authorized use only.** Every tool here talks to live infrastructure or
> intercepts your own traffic. Run them only against tenants, gateways, and
> accounts you own or are explicitly permitted to assess.

## Tools

| Folder | Name | What it does |
| --- | --- | --- |
| [`vpn_fingerprint/`](vpn_fingerprint/) | VPN Fingerprinter | Given a VPN hostname, say whether it is GlobalProtect, a Cisco ASA or a FortiGate SSL VPN, how it authenticates (SAML, password, certificate), which IdP it uses, and what it exposes before login. Also reads the TLS client-certificate request: whether a certificate is required and which CAs the server says it accepts. Can also ask one Zscaler cloud whether a company domain is registered and which IdP it uses. The front door for the rest. |
| [`netskope_scout/`](netskope_scout/) | Netskope Scout | Anonymous OrgKey discovery and read-only tenant configuration enumeration (steering exceptions, pinned apps, tunnel policy, compliance checks). |
| [`cisco_profile_lens/`](cisco_profile_lens/) | Cisco Profile Lens | Parse the pre-auth Cisco SDesktop/HostScan `data.xml` into a readable, editable posture profile, and act as an OpenConnect CSD wrapper that reports either the real machine state or that profile. |
| [`gp_recon/`](gp_recon/) | GlobalProtect Recon | Give it a portal: it says what the portal needs to sign in (password, certificate, or SAML), signs in, and reports the gateways and the CSC / HIP requirements. Identifies itself as stock OpenConnect does. Never connects to a gateway. |
| [`saml_bridge/`](saml_bridge/) | SAML Bridge | Lab TLS-intercepting proxy that injects a PRT cookie into the IdP sign-in, with a per-install name-constrained CA. |

A typical order: fingerprint the VPN hostname, then use the tool it names.
Netskope has no customer-hosted gateway to fingerprint, so `netskope_scout`
starts from the tenant name instead. `gp_recon --proxy` can route its browser
sign-in through `saml_bridge`.

## Detections

[`detections/`](detections/) holds the blue-team side of the talk: experimental Sigma rules and
Microsoft Sentinel KQL for two signals that need little infrastructure.

| Area | What it catches | Telemetry |
| --- | --- | --- |
| Client trust state | A non-vendor process reading GlobalProtect, Zscaler, Netskope or Cisco client state, the Zscaler / Netskope device ID, software-backed certificate private keys, or DPAPI master keys; plus a hunting query for live DPAPI decryption | Kernel-File ETW, or Security 4663 with the SACL from `detections/tools/Set-PtdAuditSacl.ps1`; Crypto-DPAPI Debug channel for the live query |
| OpenConnect defaults | The stock OpenConnect User-Agent and the placeholder values of its bundled HIP / CSD scripts; GlobalProtect sessions reporting client version `0.0.x` or an empty HIP serial | Gateway, web front-end and PAN-OS GlobalProtect logs |

Start with [`detections/README.md`](detections/README.md), and baseline in your own environment
before alerting ([`detections/docs/validation.md`](detections/docs/validation.md)). The GlobalProtect
signals build on rotarydrone's [GlobalUnProtect](https://github.com/rotarydrone/GlobalUnProtect)
countermeasures; see [`detections/docs/credits.md`](detections/docs/credits.md).

## Design principles

- **Recon first.** None of the tools establishes a tunnel, requests an
  enrollment certificate, or invents posture data on its own. Three tools go
  beyond pure reading, each only with input you supply:
  - Cisco Profile Lens can run as OpenConnect's CSD wrapper (the job the stock
    `csd-post.sh` does). Given a profile, it submits the values you edited
    instead of measuring the machine.
  - GlobalProtect Recon signs in with your credentials, and submits a CSC
    report only from a template you reviewed and selected. It stops with exit
    status 2 rather than submit generated placeholder data.
  - SAML Bridge is a lab MITM and is marked as such.
- **No embedded secrets.** No vendor keys, CA private keys, or real tenant data
  ship in this repository. Where a key is required you supply or generate it yourself.
- **Secrets stay off the command line.** Tools prompt for secrets or read them
  from files; none takes a password or token as an argument.
- **Output is sensitive.** Recon output, saved cookies, and generated
  templates contain tenant and session data. The `.gitignore` covers the
  default output names; review anything before sharing it.

## Requirements

Python 3.9+. Each tool that needs third-party packages has a `requirements.txt`:

| Tool | Needs |
| --- | --- |
| `vpn_fingerprint` | `requests`, `cryptography` |
| `netskope_scout` | `requests` |
| `cisco_profile_lens` | standard library only, plus `curl` 7.39+ on `PATH` |
| `gp_recon` | `requests`, `cryptography`, `playwright` (with Chromium) |
| `saml_bridge` | `cryptography` |

## License

MIT - see [`LICENSE`](LICENSE).
