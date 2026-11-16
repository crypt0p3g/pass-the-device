# SAML Bridge

**A local proxy that adds a Microsoft Primary Refresh Token (PRT) cookie to an
Entra ID sign-in.** A VPN or SASE client signs in through an embedded browser
that follows the system proxy. SAML Bridge sits in that path, and when the
browser reaches the Entra sign-in it attaches the PRT cookie you supply, so the
sign-in completes as that device and user without a password prompt.

It demonstrates one point from the talk: device trust carried by a PRT moves
with the cookie, not with the device.

> **This is a MITM tool.** Use it only in a lab or an engagement you are
> explicitly authorized to run, against accounts you control. It terminates TLS
> for the identity-provider hosts you name.

## How it works

```text
VPN client / browser ──CONNECT──▶ SAML Bridge (127.0.0.1:8888) ──TLS──▶ login.microsoftonline.com
                                        │
                                        ├─ IdP host: decrypt, add the PRT cookie
                                        │  to sign-in requests, re-encrypt
                                        └─ any other host: pass through untouched
```

1. The client sends its traffic to the bridge as an HTTP proxy.
2. For the identity-provider hosts (by default `login.microsoftonline.com` and
   `login.microsoft.com`), the bridge answers with a certificate from its own
   CA and reads the requests.
3. On sign-in requests it sets the `x-ms-RefreshTokenCredential` cookie to your
   PRT value. The cookies already on the request (`ESTSAUTH`, `buid`, `fpc`
   and others) are kept.
4. Everything else is relayed as an opaque tunnel. The bridge cannot read it:
   its CA is restricted to the identity-provider hosts and it issues no
   certificate for any other name.

Sign-in requests are those whose path contains `saml2`, `/oauth2/authorize`,
`/oauth2/v2.0/authorize`, `/login`, or `/kmsi`. Every request on a connection
is checked, including those on a reused connection.

## Install

```sh
python3 -m pip install -r requirements.txt
```

## 1. Generate the CA

```sh
python3 saml_bridge.py gen-ca
```

This writes `bridge-ca.crt` and `bridge-ca.key` in the current directory. The
CA is valid for 7 days and only for the identity-provider hosts. Add `--domain`
(repeatable) for a different IdP host. Nothing is overwritten: remove the old
files to generate a new CA. Keep `bridge-ca.key` private.

## 2. Run the proxy

The PRT value is read from a file, from stdin, or from a hidden prompt:

```sh
python3 saml_bridge.py start --prt-file prt.txt
python3 saml_bridge.py start --prt-stdin
python3 saml_bridge.py start
```

The proxy listens on `127.0.0.1:8888`. The client has to use it as its proxy
and trust `bridge-ca.crt`. There are two ways to arrange that.

**Windows, automatic.** `--install` adds the CA to the current user's Root
store, sets the system proxy, and undoes both when you stop the bridge with
Ctrl+C:

```powershell
py saml_bridge.py start --install --prt-file prt.txt
```

**Any OS, manual.** Add `bridge-ca.crt` to the trust store of the browser or
profile you are testing with, and set its proxy to `127.0.0.1:8888`.

### With `gp_recon`

`gp_recon` needs no CA install, because it does not verify TLS while a proxy
is set:

```sh
python3 saml_bridge.py start --prt-file prt.txt
../gp_recon/gp_recon.py portal.example.com --proxy 127.0.0.1:8888
```

## What it changes on your machine

| What | When | Undone |
| --- | --- | --- |
| `bridge-ca.crt`, `bridge-ca.key` in the current directory | `gen-ca` | delete them yourself |
| "SAML Bridge Lab CA" in the current user's Root store | `start --install` (Windows) | on Ctrl+C |
| System proxy set to the bridge | `start --install` (Windows) | on Ctrl+C, restored to the previous value |

If the bridge is killed instead of stopped with Ctrl+C, the last two are not
undone: remove the certificate and reset the proxy by hand. The CA expires on
its own after 7 days.

The PRT value is kept in memory only. It is never written to disk and never
logged, including with `--verbose`.

## Options

| Option | Purpose |
| --- | --- |
| `--prt-file FILE`, `--prt-stdin` | where the PRT value comes from (default: hidden prompt) |
| `--install` | Windows: install the CA and set the system proxy for the run |
| `--domain HOST` | identity-provider host to intercept (repeatable); on `gen-ca` it also restricts the CA |
| `--path-marker TEXT` | path substring that marks a sign-in request (repeatable; replaces the defaults) |
| `--cookie-name NAME` | cookie to set (default `x-ms-RefreshTokenCredential`) |
| `--listen-host`, `--listen-port` | where to listen (default `127.0.0.1:8888`) |
| `--ca-cert`, `--ca-key` | CA file paths (default `bridge-ca.crt`, `bridge-ca.key`) |
| `--verbose` | log each injection and connection error |

Keep the listener on loopback. Anyone who can reach the port and trusts the CA
gets the cookie added to their sign-in; the bridge warns if you bind elsewhere.

## Limits

- Whether Entra accepts the cookie depends on the PRT itself: nonce freshness,
  device binding, and Conditional Access. The bridge only delivers it.
- HTTP/1.1 only. The proxy does not offer HTTP/2, so clients fall back.
- Only `CONNECT` is handled; plain-HTTP proxy requests are dropped.
- A request with a chunked body or a protocol upgrade switches the rest of that
  connection to pass-through, with no further injection on it.
- An idle connection is closed after 60 seconds.
