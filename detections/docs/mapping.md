# Mapping — talk steps, ATT&CK, and coverage

## Talk step → rule

The talk walks five steps (discover, map trust, choose route, rebuild, validate) and two routes off
the host (copy existing state / enroll fresh trust). This release covers the **collection** end of
the copy route and the **OpenConnect rebuild** fingerprints.

| Talk element | Rule / query | Lane |
| --- | --- | --- |
| Copy route · read client state | `*_vpn_client_state_read` (both variants) | Endpoint |
| Copy route · match device ID | `win_security_ptd_vpn_device_id_registry_read` | Endpoint |
| Copy route · offline DPAPI decrypt | `*_dpapi_masterkey_read` (both variants) | Endpoint |
| Copy route · software certificate key | `*_private_key_file_read` (both variants) | Endpoint |
| Copy route · live DPAPI decrypt | `ptd_dpapi_live_unprotect.kql` (Crypto-DPAPI/Debug 16385) | Endpoint |
| Rebuild · OpenConnect default client | `web_ptd_openconnect_default_useragent`, `ptd_openconnect_default_literals.kql` | Gateway / web |
| Rebuild · GlobalProtect via OpenConnect | `ptd_globalprotect_openconnect_client.kql` | VPN/SASE control plane |

## ATT&CK

| Technique | ID | Where |
| --- | --- | --- |
| External Remote Services | T1133 | OpenConnect rules |
| Use Alternate Authentication Material | T1550 | client-state read rules |
| — Web Session Cookie | T1550.004 | GlobalProtect cookie reuse (credits: rotarydrone) |
| Unsecured Credentials: Private Keys | T1552.004 | client-state and private-key read rules |
| Steal or Forge Authentication Certificates | T1649 | private-key read rules |
| Credentials from Password Stores | T1555 | client-state read rules |
| — DPAPI | T1555.004 | DPAPI master-key rules, live DPAPI decrypt query |
| Query Registry | T1012 | device-ID registry rule |
| Steal Web Session Cookie | T1539 | GlobalProtect cookie (rotarydrone's original) |

Device Registration (T1098.005) and the enrollment route are **out of scope for this release** — they
live in the IdP and VPN/SASE control-plane logs, not on the endpoint, and need per-tenant field
mapping.

## Not shipped yet

The talk's strongest blue-team point is the **join** across lanes. These need your schema, so they
are documented rather than shipped:

- **One user, two hosts.** Concurrent VPN/SASE sessions or devices for one identity with different
  OS or client fingerprints. (Talk slide 47, item 3.)
- **Enrollment after an EDR alert.** A new VPN/SASE device record for a user within minutes–hours of
  an EDR/IR flag on that user or host. (Talk slide 42 / appendix A22.)
- **Transplanted session concurrent with the source.** Original host and a second session for the
  same identity active at once. (Talk slide 44, Network/NDR row.)

To build these you first normalise VPN/SASE session and enrollment events into one schema. That
normaliser is product- and ingestion-specific; start from the field list each vendor's appendix slide
gives (A17–A20) and the IR card (A24).
