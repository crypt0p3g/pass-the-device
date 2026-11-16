# Validation and tuning

Nothing here has been proven against production telemetry at scale. Treat every rule as a hypothesis
and run this before you alert on it.

## 1. Lint the Sigma

```bash
pip install sigma-cli
sigma check rules/
```

Fix any error before converting. `status: experimental` is intentional — promote to `test`/`stable`
in your own fork once you have run the rule.

## 2. Endpoint read rules

**file_access variant** needs the Microsoft-Windows-Kernel-File ETW provider in your pipeline
(many EDRs expose it; Sysmon does **not** log ordinary file reads). **Security 4663 variant** needs
`tools/Set-PtdAuditSacl.ps1 -Apply` on the host and "Audit File System / Registry (Success)" reaching
your collector.

Baseline, on a representative host, for at least a week:

1. Apply the SACL (or enable the ETW path) on a lab/pilot host.
2. Collect every reader of the covered paths with no filtering.
3. The legitimate readers you will see and must exclude after validation:
   - the vendor clients themselves (already filtered by install path),
   - backup / DLP / AV agents,
   - roaming-profile, FSLogix, USMT, Credential Roaming,
   - management agents (SCCM/Intune/Tanium) for the registry rule,
   - `lsass.exe` for the DPAPI rule (already filtered).
4. Add only validated, specific exclusions. Prefer full paths over `startswith` where you can.
   Never exclude whole folders such as `C:\Windows\System32\`: `cmd.exe`, `powershell.exe`,
   `robocopy.exe` and other built-in binaries live there, and they are the likeliest readers during
   collection. The rules ship without such folder filters on purpose.
5. Measure event volume per host before fleet rollout — DPAPI and client-state reads can be chatty.

Positive test: run an authorized copy of the technique (e.g. GlobalUnProtect, or the DPAPI toolkit)
in a lab and confirm the rule fires and the vendor-process baseline does not.

### Private-key and live-DPAPI additions

- **Private-key read rules** are the noisiest endpoint rules: any process that uses a legacy CAPI key
  (browsers or Office doing client-certificate auth or S/MIME) reads its key file in-process. CNG keys
  are used through LSASS (filtered). Baseline per image and exclude exact paths. Positive test: copy a
  software-backed test certificate's key file from a lab profile and confirm the rule fires.
- **Live DPAPI query** (`ptd_dpapi_live_unprotect.kql`): enable the Debug channel on pilot hosts only
  (`wevtutil sl Microsoft-Windows-Crypto-DPAPI/Debug /e:true`) and measure volume first. Confirm that
  `CallerProcessID` resolves through 4688 (`NewProcessId` is hex, the query converts) or join to EDR
  process events instead. Positive test: decrypt a lab VPN client's state in place with the source
  user's context and confirm the caller appears with a non-vendor image.

## 3. OpenConnect rules

- **Default User-Agent** / **default literals**: confirm which device actually logs the client
  User-Agent and HIP/CSD fields in your estate (ASA 722055, PAN-OS GlobalProtect/HIP, a reverse
  proxy). Point the custom tables in the KQL `union` at those tables. Then connect once with stock
  OpenConnect in a lab and confirm the literals appear.
- **GlobalProtect-over-OpenConnect**: the `0.0.x` client version is build- and stage-dependent.
  Verify the exact string your PAN-OS version records for a stock OpenConnect connection before you
  rely on it; newer OpenConnect sends `app-version 6.3.0-33` and `clientVer 4100`. Pair it with the
  empty-serial HIPMATCH signal, which is more stable.

## 4. False-negative notes

- An attacker who overrides `--useragent` and edits the HIP/CSD templates defeats the OpenConnect
  string rules. They do **not** defeat the endpoint read rules (the state still has to be read) or
  the cross-lane joins in `docs/mapping.md`.
- SYSTEM-scoped Zscaler state read by a SYSTEM process is not distinguishable by install-path
  filtering alone; lean on the enrollment and control-plane signals for that route.
