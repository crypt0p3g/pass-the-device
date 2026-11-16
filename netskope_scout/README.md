# Netskope Scout

**Read-only Netskope tenant reconnaissance.** Given a tenant name, Scout
recovers the tenant OrgKey from the public nsauth SAML redirect and reads the
tenant's addon configuration: the configuration version, tenant and user
client configuration, steering domains, inspection exceptions, pinned
(SSL-pinned) apps, steering categories, bypass/overlapping domains, the tunnel
policy, the PAC, managed device-compliance checks, and client update links.
With an email address it also reports whether Secure Enrollment is enabled.

> Authorized use only. Run Scout only against tenants you own or are explicitly
> permitted to assess. It talks to live Netskope infrastructure.

The tenant name is the `<x>` in `addon-<x>.goskope.com`. OrgKey discovery sends
one unauthenticated POST to `nsauth-<x>.goskope.com` to start the SAML flow and
reads the OrgKey from the returned request; everything after that is a GET. A
tenant with no IdP configured cannot be resolved this way.

## The UserKey

When Secure Enrollment is off, the tenant returns a `UserKey` for the email
address. Scout reports that one was issued and replaces the value with
`(masked)` in the report and in `--json` output. It uses the UserKey for the
remaining requests of the same run, so the per-user steering configuration is
returned.

## Install

```sh
python3 -m pip install -r requirements.txt
```

## Usage

OrgKey discovery plus tenant-wide read-only enumeration:

```sh
python3 netskope_scout.py orgkey-recon ACME
```

Add the Secure Enrollment / user-existence probe for a specific address:

```sh
python3 netskope_scout.py userkey-recon ACME user@example.com
```

Write the full structured result to a file (or `-` for stdout):

```sh
python3 netskope_scout.py orgkey-recon ACME --json acme.json
```

Default client download links:

```sh
python3 netskope_scout.py download-client
```

`--delay` sets the pause between requests (default 1.0s); `--timeout` sets the
per-request timeout (default 30s); `--verbose` reports failed requests on
stderr, by endpoint and error type. A full run makes 17 requests, or 18 with
an email address.

## Output

A readable report lists the discovered OrgKey, the Secure Enrollment state
when an email was given and the tenant's answer was clear, a findings summary
(NPA host, inspection exceptions, wildcard pinned apps, defined compliance
checks), followed by each raw configuration section. The
most useful sections for an assessment are the steering **exceptions** (traffic
that skips inspection) and the **pinned apps**. Long sections are truncated in
the readable report; `--json` has everything, plus the `findings` list and the
`secure_enrollment` state (`true`, `false`, or `null` for unknown).

A section whose endpoint did not answer is `null`. `branding` appears only when
a UserKey was issued, and `managed_checks` only for the platforms that have
checks defined. An endpoint that answered with something other than JSON (an
error page, the PAC file) is stored as text.
