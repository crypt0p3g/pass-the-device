# VPN Fingerprinter

**Given a VPN hostname, say which product answers, how it authenticates, and
what it exposes before login.** This is the front door for the other tools in
this collection: it tells you whether you are looking at GlobalProtect, a
Cisco ASA or a FortiGate SSL VPN, and which tool to run next. For any server it
also reads the TLS client-certificate request, including the certificate
authorities the server says it accepts.

> Authorized use only. Run this only against hosts you own or are explicitly
> permitted to assess. Every probe is unauthenticated and sends no credentials.

## What it reports

For each product found:

| Field | Meaning |
| --- | --- |
| `endpoint` | The URL(s) that answered |
| `auth_method` | `SAML (binding)`, `password`, `certificate required` / `certificate requested`, or `unknown` |
| `saml_destination` | Where the SAML request is sent |
| `region`, `auth_message` | GlobalProtect only: the region and login banner |
| `tunnel_groups` | Cisco only: group names, when the gateway lists them |
| `hostscan_policy`, `hostscan` | Cisco only: the policy is readable, or a posture check runs before login |

For the server as a whole, under `Client certificate (TLS handshake)`:

| Field | Meaning |
| --- | --- |
| `requested` / `not requested` | Whether the server asked for a client certificate in the handshake |
| `enforcement` | `required` (the server refuses a handshake without a certificate), `optional` (the handshake completes without one), or `unknown` |
| `certificate_types` | TLS 1.2 and older: the key types accepted |
| `accepted_ca` | One line per certificate authority the server advertises |

A GlobalProtect portal and gateway on the same host are listed separately,
since they can authenticate differently. Below the products come the identity
providers (with the tenant GUID for Entra ID) and notes, including which tool
to run next.

## How it finds that

- **GlobalProtect** — `POST /global-protect/prelogin.esp` (portal) and
  `POST /ssl-vpn/prelogin.esp` (gateway). The response states the method:
  a SAML request, a client-certificate requirement, or a plain login form.
- **Cisco ASA / Secure Client** — three requests:
  - the first message a Secure Client sends (`POST /` with a `config-auth`
    `init` document). The answer contains a login form, an SSO URL, or a
    client-certificate request, plus the tunnel-group list if enabled. For
    SSO, the gateway's own start URL is followed until it leaves for the IdP.
  - `GET /+CSCOE+/logon.html`, the browser logon page.
  - `GET /CACHE/sdesktop/data.xml`, the HostScan policy an ASA commonly serves
    before login. Only its presence is reported; parse it with
    `cisco_profile_lens`.
- **Fortinet FortiGate SSL VPN** — `GET /remote/login` (the web logon page)
  and `GET /remote/info` (what FortiClient asks first). If either answers,
  `GET /remote/saml/start` is followed to see whether it leaves for an IdP.
- **TLS** — version, cipher, and the certificate's subject, issuer, SANs,
  expiry and SHA-256.
- **Client certificate** — the `CertificateRequest` a server sends during the
  TLS handshake, which can name the CAs it accepts. It is read from a TLS 1.2
  handshake, or decrypted from a TLS 1.3 one if the server speaks only that.
  If a certificate was requested, one more handshake without a certificate
  shows whether the server refuses it. This works for any TLS server.

## What it does not do

- It cannot tell from a VPN hostname that a company uses a cloud SASE service
  such as Zscaler or Netskope; those have no customer-hosted gateway. Zscaler
  is checked by company domain instead (see below). For Netskope, start from
  the tenant name with `netskope_scout`.
- It reports no product versions.
- Cisco authentication is reported for the default tunnel group only. Other
  groups can use a different method.
- A certificate requirement is reported when the gateway asks for one. Whether
  a password is also needed afterwards is not visible without a certificate.

- The client-certificate request is seen only when it is made in the first
  handshake. A server that asks later (TLS renegotiation, or only for one
  tunnel group or URL) shows as `not requested`.
- The accepted-CA list is what the server advertises, not proof of what it
  trusts. It can be empty or differ from the trust store. `optional` means
  TLS lets you in without a certificate; the VPN service can still demand one.
- When a certificate is `required`, no HTTP probe gets through, so the product
  cannot be identified. The client-certificate section is still reported.
- FortiGate: a logon page drawn by JavaScript may hide the password form, in
  which case `auth_method` is `unknown`. Realms other than the default are
  not checked.

The Cisco `config-auth` probe follows the protocol as OpenConnect implements
it. It has been tested against a simulated gateway, not a production ASA. The
FortiGate probe has likewise been tested only against a simulated gateway.
The client-certificate reading matches `openssl s_client` against OpenSSL
test servers (TLS 1.1 to 1.3); it has not been run against a production
gateway.

## Zscaler domain check

Zscaler is asked by company domain, not by hostname. Give the email domain and
the Zscaler cloud to ask:

```sh
python3 vpn_fingerprint.py --zscaler corp.example --zscaler-cloud zscalerthree.net
python3 vpn_fingerprint.py vpn.corp.example --zscaler corp.example --zscaler-cloud zscalerthree.net
```

This sends the one request Zscaler Client Connector sends when a user types
their email address (`login.<cloud>/clstart` with the domain). The answer is:

- `registered: no` — the cloud replied "Domain not found";
- `registered: yes` — the cloud started the sign-in, with `auth_method` and,
  for SAML, the `saml_destination` and identity provider;
- `registered: unknown` — any other answer, with the detail shown.

Only the cloud you name is asked. A "no" means not on that cloud; the tool does
not try the others. Known clouds, also listed in `--help`: `zscaler.net`,
`zscalerone.net`, `zscalertwo.net`, `zscalerthree.net`, `zscloud.net`,
`zscalerbeta.net`, `zscalergov.net`, `zscalerten.net`. Any other name is
accepted as given. The cloud can be written `zscalerthree`,
`zscalerthree.net`, or `login.zscalerthree.net`.

## Install

```sh
python3 -m pip install -r requirements.txt
```

## Usage

```sh
python3 vpn_fingerprint.py vpn.example.com
python3 vpn_fingerprint.py vpn.example.com:10443
python3 vpn_fingerprint.py https://vpn.example.com/ --json result.json
python3 vpn_fingerprint.py --zscaler corp.example --zscaler-cloud zscalerthree.net
```

`--timeout` sets the per-request timeout (default 15s); `--verbose` logs each
failed probe to stderr; `--json -` writes the result to stdout. The default
port is 443; FortiGate SSL VPN often listens on another, such as 10443. The
exit status is 1 when the host cannot be reached.

## Output

```text
======================================================================
VPN fingerprint - vpn.example.com
======================================================================
TLS: TLSv1.3 | issuer: CN=Example CA

Products:
  [+] Palo Alto GlobalProtect (portal)
        endpoint: /global-protect/prelogin.esp
        region: JP
        auth_method: SAML (REDIRECT)
        auth_message: Enter login credentials
        saml_destination: https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/saml2?SAMLRequest=...

Client certificate (TLS handshake):
  [+] requested
        enforcement: optional - the handshake completes without a certificate
        certificate_types: rsa_sign, dss_sign, ecdsa_sign
        accepted_ca: CN=Corp Issuing CA 01,OU=PKI,O=Corp\, Inc.,C=JP
        accepted_ca: CN=Corp Device CA,DC=corp,DC=local

Identity providers:
  [+] Microsoft Entra ID (login.microsoftonline.com) tenant=11111111-2222-3333-4444-555555555555

Notes:
  - The accepted client-certificate CAs are readable before authentication.
  - GlobalProtect prelogin answered without authentication.
  - Next: gp_recon.
```

`--json` carries the same data plus the full TLS details and the signature
algorithms from the certificate request.

TLS verification is intentionally disabled so that self-signed or
split-horizon gateways can still be fingerprinted. Because nothing is
verified, the certificate details describe whatever answered on that address.

An identity provider is named only when its host matches a known IdP domain
exactly or as a subdomain; anything else is shown by hostname.
