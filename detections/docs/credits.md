# Credits and prior art

This detection content stands on work by others. Where a rule derives from a specific published
rule, its `related:` block names that rule's id and its `references:` link the source.

## rotarydrone — GlobalUnProtect

- Repo: https://github.com/rotarydrone/GlobalUnProtect
- Write-up: https://rotarydrone.medium.com/4a1d8fc7773e

The PoC that decrypts and collects GlobalProtect configuration, cookies and HIP files, and ships a
`countermeasures/` folder with Sigma and YARA. Two things here come directly from that work:

1. The GlobalProtect file list — `PanPortalCfg_*.dat`, `PanPUAC_*.dat`, `PanPCD_*.dat`,
   `HipPolicy.dat`, and the HIP files GlobalUnProtect collects (`HIP_*_Report_*.dat`, `PanGPHip.log`)
   — and the idea of a `file_access` rule that filters out the vendor process. `pan_gp_hrpt.xml`
   (the last HIP report, as plaintext XML) is our addition.
   Our `*_vpn_client_state_read` rules generalise rotarydrone's GlobalProtect-only rule
   (`1b5fc48c-5e17-4b3a-9575-242ccfea7f16`) to the four products in the talk. Run the original too;
   deduplicate on overlap.
2. The server-side OpenConnect signal for GlobalProtect: client version `0.0.x` at `gateway-auth`
   and an empty endpoint serial in `HIPMATCH`. Our `ptd_globalprotect_openconnect_client.kql` is a
   Sentinel/PAN-OS port of those two Sigma rules (`675fb788-...`, `2a974294-...`), not a replacement.
   If you have a GlobalProtect-category pipeline, prefer running the originals.

Their YARA (`GlobalUnProtect.yar`) matches the GlobalUnProtect assembly GUID and its string
constants — use it as well; it is specific to that tool and complementary to these behavioural rules.

## AmberWolf — NachoVPN / "Zero Trust, Total Bust"

- David Cash and Rich Warren: rogue-server attacks on SSL-VPN clients and decryption of Zscaler /
  Netskope client state (Netskope LPE CVE-2025-0309, Zscaler SAML bypass CVE-2025-54982).

Product-specific weaknesses in the same clients. The talk turns the recurring field reality into a
repeatable test; these rules watch for the collection and reuse step.

## SigmaHQ

- The DPAPI master-key `file_access` rule (`46612ae6-86be-4802-bc07-39b59feb1309`) and the SACL
  rule style (`EventID: 4663`, `%%` access masks) are SigmaHQ conventions. Our DPAPI rules overlap
  the SigmaHQ one and narrow it to the remote-access use case — deduplicate if you run both.

## OpenConnect

- https://gitlab.com/openconnect/openconnect — the default User-Agent, the bundled `trojans/`
  HIP/CSD scripts and their placeholder values are read straight from upstream source. Those
  defaults, not the project, are what the OpenConnect rules detect.
