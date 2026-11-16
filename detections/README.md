# Pass-the-Device — Detections

Detection content for **Pass-the-Device**, the CODE BLUE 2026 talk on transplanting SASE/VPN
trust after an endpoint compromise. When remote-access trust can be reproduced on a second
machine — by copying client state or by enrolling a fresh client — the original host's EDR goes
blind, but the endpoint, the IdP, the PKI and the VPN/SASE control plane still hold evidence.
These rules help you **join those lanes**.

This folder is the blue-team half of [crypt0p3g/pass-the-device](https://github.com/crypt0p3g/pass-the-device):
the recon tools in the [repository root](../README.md) show how far the trust moves, and the rules
here show where you can see it move. Offline DPAPI inspection lives in
[crypt0p3g/dpapi-toolkit](https://github.com/crypt0p3g/dpapi-toolkit).

> **Status: experimental.** Every rule here is a starting point. None has been validated against
> production telemetry at scale. Baseline the readers and sessions in your own environment before
> you alert, and tune the filters. See [`docs/validation.md`](docs/validation.md).

> **Scope.** This release covers the two signals that need almost no infrastructure: **reading the
> client trust state on the endpoint**, and **the fingerprints the stock OpenConnect client leaves**.
> Cross-lane correlation (one user on two hosts, enrollment after an EDR alert) is called out in
> [`docs/mapping.md`](docs/mapping.md) but not shipped as finished queries yet.

## Layout

```
rules/
  endpoint/
    file_access/        Sigma, Microsoft-Windows-Kernel-File ETW (no SACL needed)
    builtin_security/   Sigma, Security log event 4663 (needs the SACL from tools/)
  openconnect/          Sigma, web-server / gateway logs
hunting/
  kql/                  Microsoft Sentinel queries (same logic, plus GlobalProtect-over-OpenConnect)
tools/
  Set-PtdAuditSacl.ps1  Enables read auditing for the 4663 rules
docs/
  mapping.md            ATT&CK + talk-step mapping, what is and is not covered
  validation.md         How to test each rule and baseline false positives
  credits.md            Prior art this builds on
```

## Rules

### Endpoint — reading the client trust state

The copy route of Pass-the-Device begins by reading the files and registry values that hold the
remote-access proof. Two interchangeable variants, pick the telemetry you already collect:

| File | Telemetry | Needs SACL |
| --- | --- | --- |
| `rules/endpoint/file_access/file_access_win_ptd_vpn_client_state_read.yml` | Kernel-File ETW | no |
| `rules/endpoint/file_access/file_access_win_ptd_dpapi_masterkey_read.yml` | Kernel-File ETW | no |
| `rules/endpoint/builtin_security/win_security_ptd_vpn_client_state_read.yml` | Security 4663 | yes |
| `rules/endpoint/builtin_security/win_security_ptd_vpn_device_id_registry_read.yml` | Security 4663 | yes |
| `rules/endpoint/builtin_security/win_security_ptd_dpapi_masterkey_read.yml` | Security 4663 | yes |
| `rules/endpoint/file_access/file_access_win_ptd_private_key_file_read.yml` | Kernel-File ETW | no |
| `rules/endpoint/builtin_security/win_security_ptd_private_key_file_read.yml` | Security 4663 | yes |
| `hunting/kql/ptd_dpapi_live_unprotect.kql` | Crypto-DPAPI/Debug 16385 + 4688 | no (Debug channel must be enabled) |

Covered state: GlobalProtect `PanPortalCfg`/`PanPUAC`/`PanPCD` and the HIP state (`HipPolicy.dat`,
`HIP_*_Report_*.dat`, `pan_gp_hrpt.xml`, `PanGPHip.log`), Zscaler
`log_<SID>\*.dat`, Netskope `stagent\data`, Cisco Secure Client / AnyConnect `preferences`, VPN
profiles and HostScan/posture `cscan.log`, the Zscaler `MtGuid` and Netskope `nsdeviceuid` registry
values, software-backed certificate private keys (user and machine CAPI/CNG key stores), and the DPAPI
master keys used to decrypt all of the above offline.

Decryption itself is covered two ways: **offline** (the master keys and key files are read and copied,
caught by the read rules above) and **live** (`CryptUnprotectData` on the host, visible only in the
Crypto-DPAPI Debug channel, event 16385). The live case is a hunting query rather than a Sigma rule:
the event carries only the caller's PID, so it has to be joined to process creation, and the channel
is off by default.

For the 4663 variants, run `tools/Set-PtdAuditSacl.ps1` first — without the SACL there are no events.
It is a dry run until you pass `-Apply`, and `-Remove` reverts exactly what it added.

### OpenConnect — default-client fingerprints

Stock OpenConnect leaves recognisable traces unless the operator overrides them:

- `rules/openconnect/web_ptd_openconnect_default_useragent.yml` — the default User-Agent
  (`AnyConnect-compatible OpenConnect VPN Agent` / `Open AnyConnect VPN Agent`) in front-end web logs.
- `hunting/kql/ptd_openconnect_default_literals.kql` — default values from the bundled
  `trojans/hipreport.sh` and `csd-post.sh`: host-id `deadbeef-...`, MAC `01-02-03-00-00-01` and
  `FFFF.FFFF.FFFF`, `IPTablesFW`, `Linux Fedora 32`, etc.
- `hunting/kql/ptd_globalprotect_openconnect_client.kql` — the **GlobalProtect** case, where the
  User-Agent is identical to the real client: the gateway instead sees client version `0.0.x` at
  `gateway-auth` and an empty serial in `HIPMATCH` (signals documented by rotarydrone).

Values were verified against OpenConnect upstream `master` (`v9.21-25-g70d1e79`, 2026-07-19).

## Using the Sigma rules

```bash
pip install sigma-cli pysigma-backend-splunk pysigma-backend-microsoft365defender
sigma check rules/
# convert, e.g. to Microsoft Sentinel:
sigma convert -t kusto rules/endpoint/file_access/
```

## Credits

This builds on **rotarydrone**'s [GlobalUnProtect](https://github.com/rotarydrone/GlobalUnProtect)
and its `countermeasures` Sigma/YARA, on **AmberWolf**'s NachoVPN research, and on the OpenConnect
project. Full list in [`docs/credits.md`](docs/credits.md).

## Licence

MIT, same as the rest of the repository. See [`LICENSE`](../LICENSE). Rules are provided as-is
for authorized defensive use.
