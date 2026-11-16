# Cisco Profile Lens

**Read a Cisco ASA's HostScan policy and turn it into an editable posture
profile that OpenConnect can submit.** A Cisco ASA commonly serves the policy
(`data.xml`) before authentication, so the checks a client must pass are
readable by anyone. Profile Lens replaces the brittle `xmlstarlet`/`sed` logic
in the stock OpenConnect `csd-post.sh` with a real parser and a JSON profile
you can review.

> Authorized use only. Use this against gateways you own or are explicitly
> permitted to test.

Requires Python 3.9+ (standard library only) and `curl` 7.39+ on `PATH`.

## 1. See what the gateway checks

```sh
./cisco_profile_lens.py show https://vpn.example.com/
```

```text
3 posture check(s):

  TYPE      LABEL     TARGET
  File      hosts     C:\Windows\System32\drivers\etc\hosts
  Process   defender  MsMpEng.exe
  Registry  domain    HKEY_LOCAL_MACHINE\SYSTEM\...\Tcpip\Parameters\Domain
```

A base URL is looked up at `/CACHE/sdesktop/data.xml`. The input can also be a
saved `data.xml` file or `-` for stdin. A bare URL with no command means
`show`; `--json` prints the checks as JSON. TLS is validated normally.

Only `File`, `Process`, and `Registry` checks are evaluated.
`cInspectorExtension*` entries are listed and kept in the profile as metadata.

## 2. Save an editable profile

```sh
./cisco_profile_lens.py save https://vpn.example.com/ profile.json
```

Each check gets an `expected` block, and `expected_endpoint` carries
antimalware / firewall / OS / device records. The file is prefilled with
example values (a Windows 11 host, Defender, a firewall entry, typical install
paths for known agent process names, and `REPLACE` where nothing is known).
**Nothing in it is read from a real device.** Replace the values with those of
the endpoint you are authorized to represent.

## 3. Preview what would be submitted

```sh
./cisco_profile_lens.py preview profile.json
```

This prints the plaintext report built from the profile's values. Two options:

- `--observed` evaluates the profile's checks on the machine you run it on,
  instead of using the values in the file.
- `--http vpn.example.com` wraps the report as the raw `scan.xml` request, with
  a `REPLACE_SESSION_TOKEN` cookie, for reading rather than replaying.

## 4. Use it with OpenConnect

```sh
./cisco_profile_lens.py openconnect profile.json
```

This writes `profile-openconnect.sh` and `profile-openconnect.conf` next to the
profile (`--prefix` changes the location) and prints the command to run:

```sh
sudo openconnect --protocol=anyconnect \
  --config=/absolute/path/profile-openconnect.conf vpn.example.com
```

OpenConnect then runs the wrapper at the HostScan stage, and the wrapper
submits the profile's values. Running `profile-openconnect.sh` by hand only
prints the preview.

### Without a profile

OpenConnect can also run the script directly. It then downloads `data.xml` and
reports the real state of the local machine:

```sh
sudo openconnect --protocol=anyconnect \
  --csd-wrapper=/absolute/path/cisco_profile_lens.py vpn.example.com
```

On macOS and Linux, Windows Registry checks are reported as not present.

## Notes

- When OpenConnect supplies `CSD_SHA256`, curl is pinned to the same key.
- Native Windows OpenConnect does not execute CSD wrappers.
- `TOKEN_SUCCESS` / `TOKEN_LOGGEDON` acknowledges the submission. It does not
  prove that a DAP policy permits access. No successful gateway login has been
  verified in the development environment.
- `SDESKTOP_SHOW_HTTP=1` traces the wrapper's HTTP exchange to stderr. The
  trace includes the session token.
- `SDESKTOP_TLS_CONFIG=/path/to/curl.conf` adds a curl config file, for example
  a CA bundle or client certificate.
- Status lines are prefixed `cisco-profile-lens:`.
