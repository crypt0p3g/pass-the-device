#!/usr/bin/env python3
"""Client-certificate request probe.

When a TLS server wants a client certificate it sends a CertificateRequest
message during the handshake. That message can carry the list of certificate
authorities the server accepts (distinguished names), plus the certificate
types and signature algorithms it supports. Any client receives it before
authenticating, so the list of accepted CAs is readable by anyone who can
reach the port.

This tool starts a TLS handshake, reads that message, and prints it. It works
at the TLS layer, so it is the same for every product that asks for a
certificate in the handshake: Cisco ASA / Secure Client (AnyConnect), Palo
Alto GlobalProtect, Fortinet FortiGate SSL VPN, and anything else.

TLS 1.2 is tried first because the message is sent in the clear there and
needs only the standard library. If the server refuses TLS 1.2, TLS 1.3 is
used, where the message is encrypted with handshake keys (needs the
'cryptography' package).

vpn_fingerprint.py runs this probe as part of its report.

No certificate, credentials or HTTP request are sent. Use only against hosts
you own or are explicitly permitted to assess.
"""

import hashlib
import hmac
import ipaddress
import os
import socket
import ssl
import struct

HANDSHAKE, ALERT, CHANGE_CIPHER_SPEC, APPLICATION_DATA = 22, 21, 20, 23
MAX_HANDSHAKE_BYTES = 1 << 20  # stop reading a flight that is absurdly large

# Offered in the TLS 1.2 hello. Deliberately broad: the goal is to get any
# ServerHello back, not to negotiate something strong.
TLS12_CIPHER_SUITES = (
    0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0xC009,
    0xC00A, 0xC027, 0xC028, 0xC023, 0xC024, 0x009C, 0x009D, 0x002F, 0x0035,
    0x003C, 0x003D, 0x009E, 0x009F, 0x0033, 0x0039, 0x0067, 0x006B, 0x000A,
    0x00FF,  # renegotiation-info SCSV
)
# TLS 1.3 suite -> (hash name, AEAD key length, AEAD name)
TLS13_CIPHER_SUITES = {
    0x1301: ("sha256", 16, "aesgcm"),
    0x1302: ("sha384", 32, "aesgcm"),
    0x1303: ("sha256", 32, "chacha20"),
}
SIGNATURE_SCHEMES = {
    0x0201: "rsa_pkcs1_sha1", 0x0202: "dsa_sha1", 0x0203: "ecdsa_sha1",
    0x0301: "rsa_pkcs1_sha224", 0x0302: "dsa_sha224", 0x0303: "ecdsa_sha224",
    0x0402: "dsa_sha256", 0x0502: "dsa_sha384", 0x0602: "dsa_sha512",
    0x081A: "ecdsa_brainpoolP256r1tls13_sha256",
    0x081B: "ecdsa_brainpoolP384r1tls13_sha384",
    0x081C: "ecdsa_brainpoolP512r1tls13_sha512",
    0x0904: "mldsa44", 0x0905: "mldsa65", 0x0906: "mldsa87",
    0x0401: "rsa_pkcs1_sha256", 0x0403: "ecdsa_secp256r1_sha256",
    0x0501: "rsa_pkcs1_sha384", 0x0503: "ecdsa_secp384r1_sha384",
    0x0601: "rsa_pkcs1_sha512", 0x0603: "ecdsa_secp521r1_sha512",
    0x0804: "rsa_pss_rsae_sha256", 0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512", 0x0807: "ed25519", 0x0808: "ed448",
    0x0809: "rsa_pss_pss_sha256", 0x080A: "rsa_pss_pss_sha384",
    0x080B: "rsa_pss_pss_sha512",
}
OFFERED_SIGNATURE_SCHEMES = (
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0807,
    0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
)
CERTIFICATE_TYPES = {
    1: "rsa_sign", 2: "dss_sign", 3: "rsa_fixed_dh", 4: "dss_fixed_dh",
    64: "ecdsa_sign", 65: "rsa_fixed_ecdh", 66: "ecdsa_fixed_ecdh",
}
ALERTS = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
    40: "handshake_failure", 42: "bad_certificate", 43: "unsupported_certificate",
    46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca",
    49: "access_denied", 50: "decode_error", 51: "decrypt_error",
    70: "protocol_version", 71: "insufficient_security", 80: "internal_error",
    86: "inappropriate_fallback", 109: "missing_extension",
    112: "unrecognized_name", 116: "certificate_required",
    120: "no_application_protocol",
}
DN_ATTRIBUTES = {
    "2.5.4.3": "CN", "2.5.4.4": "SN", "2.5.4.5": "serialNumber",
    "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.9": "street",
    "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.12": "title",
    "2.5.4.42": "GN", "2.5.4.97": "organizationIdentifier",
    "0.9.2342.19200300.100.1.1": "UID", "0.9.2342.19200300.100.1.25": "DC",
    "1.2.840.113549.1.9.1": "emailAddress",
}
HELLO_RETRY_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)


class TLSAlert(Exception):
    def __init__(self, description):
        self.description = description
        super().__init__(f"TLS alert: {ALERTS.get(description, description)}")


class ProbeError(Exception):
    pass


# -- DER (just enough to print a distinguished name) -----------------------
def _der_read(data, pos):
    """Return (tag, content, end_offset) of the DER element at pos."""
    if pos + 2 > len(data):
        raise ValueError("truncated DER")
    tag, length = data[pos], data[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or pos + count > len(data):
            raise ValueError("bad DER length")
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    if pos + length > len(data):
        raise ValueError("truncated DER")
    return tag, data[pos:pos + length], pos + length


def _oid_string(content):
    if not content:
        return ""
    arcs, value = [], 0
    for byte in content:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    first = min(arcs[0] // 40, 2)
    return ".".join(str(arc) for arc in [first, arcs[0] - 40 * first] + arcs[1:])


def _der_string(tag, content):
    if tag == 0x1E:  # BMPString
        return content.decode("utf-16-be", "replace")
    if tag == 0x1C:  # UniversalString
        return content.decode("utf-32-be", "replace")
    if tag in (0x0C, 0x13, 0x14, 0x16, 0x12, 0x1A, 0x1B):
        return content.decode("utf-8", "replace")
    return "#" + content.hex()


def _escape_dn_value(value):
    out = "".join("\\" + ch if ch in ',+"\\<>;=' else ch for ch in value)
    if out.startswith((" ", "#")):
        out = "\\" + out
    if out.endswith(" "):
        out = out[:-1] + "\\ "
    # Control characters would let a hostile server rewrite terminal output.
    return "".join(ch if ch.isprintable() else f"\\{ord(ch):02x}" for ch in out)


def decode_dn(der):
    """A DER Name as an RFC 4514 style string (most specific part first)."""
    try:
        tag, sequence, _ = _der_read(der, 0)
        if tag != 0x30:
            raise ValueError("not a Name")
        rdns, pos = [], 0
        while pos < len(sequence):
            _, rdn, pos = _der_read(sequence, pos)
            parts, inner = [], 0
            while inner < len(rdn):
                _, pair, inner = _der_read(rdn, inner)
                _, oid, after_oid = _der_read(pair, 0)
                value_tag, value, _ = _der_read(pair, after_oid)
                name = _oid_string(oid)
                parts.append(
                    f"{DN_ATTRIBUTES.get(name, name)}="
                    f"{_escape_dn_value(_der_string(value_tag, value))}"
                )
            rdns.append("+".join(parts))
        return ",".join(reversed(rdns)) or "(empty name)"
    except (ValueError, IndexError):
        return "(undecodable name: " + der.hex() + ")"


# -- TLS wire helpers ------------------------------------------------------
def _recv_exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ProbeError("connection closed by the server during the handshake")
        data += chunk
    return data


def _read_record(sock):
    header = _recv_exact(sock, 5)
    content_type, _, length = struct.unpack("!BHH", header)
    if content_type not in (HANDSHAKE, ALERT, CHANGE_CIPHER_SPEC, APPLICATION_DATA):
        raise ProbeError("the server did not answer with TLS")
    if length > 0x4800:
        raise ProbeError("oversized TLS record")
    return content_type, header, _recv_exact(sock, length)


def _vector(data, length_bytes):
    return len(data).to_bytes(length_bytes, "big") + data


def _extension(ext_type, data):
    return struct.pack("!HH", ext_type, len(data)) + data


def _use_sni(name):
    if not name:
        return False
    try:
        ipaddress.ip_address(name)
        return False
    except ValueError:
        return True


def _client_hello(sni, key_shares=None):
    """A ClientHello for TLS 1.2, or for TLS 1.3 when key_shares is given."""
    tls13 = key_shares is not None
    suites = tuple(TLS13_CIPHER_SUITES) if tls13 else TLS12_CIPHER_SUITES
    extensions = b""
    if _use_sni(sni):
        name = sni.encode("idna")
        extensions += _extension(0, _vector(b"\x00" + _vector(name, 2), 2))
    groups = (0x001D, 0x0017, 0x0018) if tls13 else (0x001D, 0x0017, 0x0018, 0x0019)
    extensions += _extension(10, _vector(b"".join(struct.pack("!H", g) for g in groups), 2))
    extensions += _extension(
        13, _vector(b"".join(struct.pack("!H", s) for s in OFFERED_SIGNATURE_SCHEMES), 2)
    )
    if tls13:
        extensions += _extension(43, _vector(struct.pack("!H", 0x0304), 1))
        shares = b"".join(struct.pack("!H", g) + _vector(k, 2) for g, k in key_shares)
        extensions += _extension(51, _vector(shares, 2))
    else:
        extensions += _extension(11, _vector(b"\x00", 1))  # uncompressed points
        extensions += _extension(23, b"")                  # extended master secret
    body = (
        struct.pack("!H", 0x0303)
        + os.urandom(32)
        + _vector(os.urandom(32) if tls13 else b"", 1)
        + _vector(b"".join(struct.pack("!H", s) for s in suites), 2)
        + _vector(b"\x00", 1)
        + _vector(extensions, 2)
    )
    return b"\x01" + _vector(body, 3)


def _record(content_type, payload, version=0x0301):
    return struct.pack("!BHH", content_type, version, len(payload)) + payload


def _split_handshake(buffer):
    """Pop complete handshake messages off buffer; return (messages, rest)."""
    messages = []
    while len(buffer) >= 4:
        length = int.from_bytes(buffer[1:4], "big")
        if len(buffer) < 4 + length:
            break
        messages.append((buffer[0], buffer[4:4 + length], buffer[:4 + length]))
        buffer = buffer[4 + length:]
    return messages, buffer


def _parse_server_hello(body):
    version = struct.unpack("!H", body[:2])[0]
    random = body[2:34]
    pos = 34
    pos += 1 + body[pos]  # session id
    cipher = struct.unpack("!H", body[pos:pos + 2])[0]
    pos += 3  # cipher suite + compression method
    extensions = {}
    if pos + 2 <= len(body):
        end = pos + 2 + struct.unpack("!H", body[pos:pos + 2])[0]
        pos += 2
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack("!HH", body[pos:pos + 4])
            extensions[ext_type] = body[pos + 4:pos + 4 + ext_len]
            pos += 4 + ext_len
    if 43 in extensions and len(extensions[43]) >= 2:
        version = struct.unpack("!H", extensions[43][:2])[0]
    return version, random, cipher, extensions


def _parse_dn_list(data):
    names, pos = [], 0
    while pos + 2 <= len(data):
        length = struct.unpack("!H", data[pos:pos + 2])[0]
        names.append(decode_dn(data[pos + 2:pos + 2 + length]))
        pos += 2 + length
    return names


def _scheme_names(data):
    return [
        SIGNATURE_SCHEMES.get(code, f"0x{code:04x}")
        for (code,) in struct.iter_unpack("!H", data[:len(data) // 2 * 2])
    ]


def _parse_certificate_request(body, version):
    """CertificateRequest for TLS <= 1.2 (RFC 5246 7.4.4) or 1.3 (RFC 8446 4.3.2)."""
    request = {"certificate_types": [], "signature_algorithms": [], "ca_names": []}
    if version >= 0x0304:
        pos = 1 + body[0]  # certificate_request_context
        end = pos + 2 + struct.unpack("!H", body[pos:pos + 2])[0]
        pos += 2
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack("!HH", body[pos:pos + 4])
            data = body[pos + 4:pos + 4 + ext_len]
            pos += 4 + ext_len
            if ext_type == 47 and len(data) >= 2:    # certificate_authorities
                request["ca_names"] = _parse_dn_list(data[2:])
            elif ext_type == 13 and len(data) >= 2:  # signature_algorithms
                request["signature_algorithms"] = _scheme_names(data[2:])
        return request
    count = body[0]
    request["certificate_types"] = [
        CERTIFICATE_TYPES.get(code, str(code)) for code in body[1:1 + count]
    ]
    pos = 1 + count
    if version >= 0x0303:
        length = struct.unpack("!H", body[pos:pos + 2])[0]
        request["signature_algorithms"] = _scheme_names(body[pos + 2:pos + 2 + length])
        pos += 2 + length
    length = struct.unpack("!H", body[pos:pos + 2])[0]
    request["ca_names"] = _parse_dn_list(body[pos + 2:pos + 2 + length])
    return request


def _new_result():
    return {
        "requested": False,
        "certificate_types": [],
        "signature_algorithms": [],
        "ca_names": [],
    }


# -- TLS 1.2 and older: the server flight is plaintext ---------------------
def probe_tls12(host, port, sni, timeout):
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(_record(HANDSHAKE, _client_hello(sni)))
        result, version, buffer, total = None, None, b"", 0
        while True:
            content_type, _, payload = _read_record(sock)
            if content_type == ALERT:
                raise TLSAlert(payload[1] if len(payload) > 1 else -1)
            if content_type != HANDSHAKE:
                continue
            total += len(payload)
            if total > MAX_HANDSHAKE_BYTES:
                raise ProbeError("server handshake flight too large")
            messages, buffer = _split_handshake(buffer + payload)
            for msg_type, body, _ in messages:
                if msg_type == 2:
                    version = _parse_server_hello(body)[0]
                    if version >= 0x0304:
                        raise ProbeError("server chose TLS 1.3 for a TLS 1.2 hello")
                    result = _new_result()
                elif result is None:
                    raise ProbeError("handshake message before ServerHello")
                elif msg_type == 13:
                    result["requested"] = True
                    result.update(_parse_certificate_request(body, version))
                elif msg_type == 14:  # ServerHelloDone: nothing more to learn
                    try:
                        sock.sendall(_record(ALERT, b"\x01\x00", version))  # close_notify
                    except OSError:
                        pass
                    return result


# -- TLS 1.3: the request is encrypted with handshake keys -----------------
def _hkdf_extract(hash_name, salt, key_material):
    return hmac.new(salt, key_material, hash_name).digest()


def _hkdf_expand_label(hash_name, secret, label, context, length):
    full_label = b"tls13 " + label
    info = struct.pack("!H", length) + _vector(full_label, 1) + _vector(context, 1)
    output, block, counter = b"", b"", 1
    while len(output) < length:
        block = hmac.new(secret, block + info + bytes([counter]), hash_name).digest()
        output += block
        counter += 1
    return output[:length]


def probe_tls13(host, port, sni, timeout):
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, x25519
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    except ImportError:
        raise ProbeError(
            "this server only speaks TLS 1.3; install 'cryptography' to read its request"
        )

    x_key = x25519.X25519PrivateKey.generate()
    # One key share per group offered, so the server never has to ask again.
    curves = {0x0017: ec.SECP256R1(), 0x0018: ec.SECP384R1()}
    ec_keys = {group: ec.generate_private_key(curve) for group, curve in curves.items()}
    shares = [(0x001D, x_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw))]
    shares += [
        (group, key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
        for group, key in ec_keys.items()
    ]
    hello = _client_hello(sni, key_shares=shares)

    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(_record(HANDSHAKE, hello))
        transcript, buffer = hello, b""
        result = version = aead = iv = None
        sequence = total = 0
        while True:
            content_type, header, payload = _read_record(sock)
            if content_type == CHANGE_CIPHER_SPEC:
                continue  # middlebox-compatibility filler
            if content_type == APPLICATION_DATA:
                if aead is None:
                    raise ProbeError("encrypted record before ServerHello")
                nonce = (int.from_bytes(iv, "big") ^ sequence).to_bytes(12, "big")
                sequence += 1
                try:
                    plaintext = aead.decrypt(nonce, payload, header).rstrip(b"\x00")
                except InvalidTag:
                    raise ProbeError("could not decrypt the TLS 1.3 handshake")
                if not plaintext:
                    raise ProbeError("empty TLS 1.3 record")
                content_type, payload = plaintext[-1], plaintext[:-1]
            if content_type == ALERT:
                raise TLSAlert(payload[1] if len(payload) > 1 else -1)
            if content_type != HANDSHAKE:
                continue
            total += len(payload)
            if total > MAX_HANDSHAKE_BYTES:
                raise ProbeError("server handshake flight too large")
            messages, buffer = _split_handshake(buffer + payload)
            for msg_type, body, raw in messages:
                if msg_type == 2:
                    version, random, cipher, extensions = _parse_server_hello(body)
                    if random == HELLO_RETRY_RANDOM:
                        raise ProbeError(
                            "server asked for a key-exchange group this tool does not offer"
                        )
                    if version != 0x0304 or cipher not in TLS13_CIPHER_SUITES or 51 not in extensions:
                        raise ProbeError("server did not negotiate TLS 1.3")
                    group, key_len = struct.unpack("!HH", extensions[51][:4])
                    peer = extensions[51][4:4 + key_len]
                    if group == 0x001D:
                        shared = x_key.exchange(x25519.X25519PublicKey.from_public_bytes(peer))
                    elif group in ec_keys:
                        shared = ec_keys[group].exchange(
                            ec.ECDH(),
                            ec.EllipticCurvePublicKey.from_encoded_point(curves[group], peer),
                        )
                    else:
                        raise ProbeError("server chose an unexpected key-exchange group")
                    hash_name, key_len, aead_name = TLS13_CIPHER_SUITES[cipher]
                    size = hashlib.new(hash_name).digest_size
                    transcript += raw
                    early = _hkdf_extract(hash_name, b"\x00" * size, b"\x00" * size)
                    derived = _hkdf_expand_label(
                        hash_name, early, b"derived", hashlib.new(hash_name).digest(), size)
                    handshake_secret = _hkdf_extract(hash_name, derived, shared)
                    server_secret = _hkdf_expand_label(
                        hash_name, handshake_secret, b"s hs traffic",
                        hashlib.new(hash_name, transcript).digest(), size)
                    key = _hkdf_expand_label(hash_name, server_secret, b"key", b"", key_len)
                    iv = _hkdf_expand_label(hash_name, server_secret, b"iv", b"", 12)
                    aead = AESGCM(key) if aead_name == "aesgcm" else ChaCha20Poly1305(key)
                    result = _new_result()
                elif result is None:
                    raise ProbeError("handshake message before ServerHello")
                elif msg_type == 13:
                    result["requested"] = True
                    result.update(_parse_certificate_request(body, version))
                elif msg_type in (11, 20):
                    # The request, if any, precedes Certificate and Finished.
                    return result


# -- is the certificate mandatory at the TLS layer? ------------------------
def check_enforcement(host, port, sni, timeout):
    """Complete a normal handshake with no client certificate and see if the
    server refuses it. Sends no application data."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")  # old gateways, weak parameters
    except ssl.SSLError:
        pass
    server_name = sni if _use_sni(sni) else None
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_name) as tls:
                # In TLS 1.3 the refusal arrives after our side has finished.
                tls.settimeout(min(timeout, 4))
                try:
                    tls.recv(1)
                except (socket.timeout, TimeoutError):
                    pass
                return "optional", "the handshake completes without a certificate"
    except ssl.SSLError as exc:
        reason = getattr(exc, "reason", None) or ""
        if "ALERT" in reason:
            alert = reason.split("ALERT_", 1)[-1].lower()
            return "required", f"the server refuses a handshake without one ({alert})"
        return "unknown", f"handshake failed: {reason or exc.__class__.__name__}"
    except OSError as exc:
        return "unknown", f"connection failed: {exc.__class__.__name__}"


# -- driver ----------------------------------------------------------------
def probe(hostname, port, timeout, log):
    """The server's client-certificate request, or {"error": ...}."""
    result = {}
    try:
        try:
            result = probe_tls12(hostname, port, hostname, timeout)
        except TLSAlert as exc:
            log(f"TLS 1.2 hello refused ({exc}); trying TLS 1.3")
            result = probe_tls13(hostname, port, hostname, timeout)
    except (TLSAlert, ProbeError) as exc:
        return {"error": str(exc)}
    except (struct.error, IndexError, ValueError):
        return {"error": "malformed TLS handshake from the server"}
    except OSError as exc:
        return {"error": str(exc) or exc.__class__.__name__}
    if result["requested"]:
        log("checking whether a handshake without a certificate is refused")
        state, detail = check_enforcement(hostname, port, hostname, timeout)
        result["enforcement"] = state
        result["enforcement_detail"] = detail
    return result



