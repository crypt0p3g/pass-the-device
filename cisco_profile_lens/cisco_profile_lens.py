#!/usr/bin/env python3
"""Cisco Profile Lens: read a Cisco ASA's HostScan policy (data.xml) and turn
it into an editable posture profile that OpenConnect can submit.

Commands:

  cisco_profile_lens.py show   URL_OR_DATA_XML          list the posture checks
  cisco_profile_lens.py save   URL_OR_DATA_XML PROFILE  write an editable profile
  cisco_profile_lens.py preview PROFILE                 print what would be submitted
  cisco_profile_lens.py openconnect PROFILE             write the OpenConnect wrapper

A bare gateway URL is shorthand for "show". A base URL is looked up at
/CACHE/sdesktop/data.xml; "-" reads data.xml from stdin.

OpenConnect can also run this file directly as its CSD wrapper
(--csd-wrapper=/absolute/path/cisco_profile_lens.py). Without a profile it
downloads data.xml and reports the state of the local machine.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import platform
import re
import shlex
import socket
import subprocess
import sys
import time
import urllib.parse
import xml.etree.ElementTree as ET
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path, PureWindowsPath
from typing import Iterable, Sequence


SUPPORTED_KINDS = {"file": "File", "process": "Process", "registry": "Registry"}
PROFILE_FORMAT = "cisco-sdesktop-profile-v1"
DEFAULT_EXPECTED_PROCESS_PATHS = {
    "sophosfs.exe": r"%ProgramFiles%\Sophos\Sophos File Scanner\SophosFS.exe",
    "avp.exe": r"%ProgramFiles%\Kaspersky Lab\Kaspersky Endpoint Security for Windows\avp.exe",
    "psuaservice.exe": r"%ProgramFiles(x86)%\Panda Security\Panda Security Protection\PSUAService.exe",
    "ekrn.exe": r"%ProgramFiles%\ESET\ESET Security\ekrn.exe",
    "csfalconservice.exe": r"%ProgramFiles%\CrowdStrike\CSFalconService.exe",
    "msmpeng.exe": r"%ProgramData%\Microsoft\Windows Defender\Platform\4.18.26090.7-0\MsMpEng.exe",
    "eraagent.exe": r"%ProgramFiles%\ESET\RemoteAdministrator\Agent\ERAAgent.exe",
    "fsdevcon.exe": r"%ProgramFiles(x86)%\F-Secure\PSB\fsdevcon.exe",
    "cramtray.exe": r"%ProgramFiles%\CrowdStrike\CrAmTray.exe",
}
DEFAULT_EXPECTED_REGISTRY_VALUES = {
    r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Domain": "corp.example",
    r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\ComputerName\ActiveComputerName\ComputerName": "EXAMPLE-HOST",
}
DEFAULT_EXPECTED_OS = {
    "version": "Windows 11",
    "servicepack": "",
    "architecture": "x64",
    "processor_level": "unknown",
}
DEFAULT_EXPECTED_DEVICE = {
    "hostname": "EXAMPLE-HOST",
    "id": "SERIAL0000",
    "protection": "internal",
    "protection_version": "4.10.05085",
    "protection_extension": "3.6.4900.2",
}
DEFAULT_EXPECTED_ENFORCE = "success"
DEFAULT_EXPECTED_ANTIMALWARE = {
    "362": {
        "exists": True,
        "description": "Windows Defender",
    },
}
DEFAULT_EXPECTED_FIREWALL = {
    "MSWindowsFW": {
        "exists": True,
        "description": "Microsoft Windows Firewall",
        "version": "7",
        "enabled": "ok",
    }
}


class SDesktopError(RuntimeError):
    """A user-facing parse, collection, or transport failure."""


@dataclass(frozen=True)
class PostureCheck:
    kind: str
    label: str
    target: str


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def extract_xml(raw: bytes) -> bytes:
    """Return the XML document in raw, skipping a BOM or leading whitespace."""
    raw = raw.lstrip(b"\xef\xbb\xbf\x00\t\r\n ")
    starts = [position for marker in (b"<?xml", b"<data", b"<hostscan")
              if (position := raw.find(marker)) >= 0]
    if not starts:
        raise SDesktopError("no XML document found in input")
    return raw[min(starts) :]


def _parse_triplet(value: str) -> tuple[str, str, str] | None:
    """Parse Cisco's single-quoted CSV tuple: 'Type','label','target'."""
    try:
        rows = list(csv.reader(io.StringIO(value), delimiter=",", quotechar="'",
                               doublequote=True, skipinitialspace=True, strict=True))
    except csv.Error:
        return None
    if len(rows) != 1 or len(rows[0]) != 3:
        return None
    return tuple(part.strip() for part in rows[0])  # type: ignore[return-value]


def parse_data_xml(raw: bytes) -> list[PostureCheck]:
    """Return actionable HostScan checks from Cisco data.xml."""
    if re.search(br"<!\s*(?:DOCTYPE|ENTITY)\b", raw, re.IGNORECASE):
        raise SDesktopError("DTD and entity declarations are not accepted")
    xml = extract_xml(raw)
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise SDesktopError(f"invalid SDesktop XML: {exc}") from exc

    hostscan_nodes = [node for node in root.iter() if _local_name(node.tag) == "hostscan"]
    if not hostscan_nodes:
        raise SDesktopError("XML has no <hostscan> section")

    checks: list[PostureCheck] = []
    seen: set[tuple[str, str, str]] = set()
    for hostscan in hostscan_nodes:
        for field in hostscan.iter():
            if _local_name(field.tag) != "field":
                continue
            value = field.get("value", "")
            triplet = _parse_triplet(value)
            if not triplet:
                continue
            raw_kind, label, target = triplet
            kind = SUPPORTED_KINDS.get(raw_kind.casefold())
            if not kind or not label or not target:
                continue
            key = (kind, label, target)
            if key not in seen:
                checks.append(PostureCheck(kind, label, target))
                seen.add(key)
    return checks


def parse_inspector_extensions(raw: bytes) -> list[dict[str, object]]:
    """Preserve cInspectorExtension metadata from an SDesktop document."""
    if re.search(br"<!\s*(?:DOCTYPE|ENTITY)\b", raw, re.IGNORECASE):
        raise SDesktopError("DTD and entity declarations are not accepted")
    try:
        root = ET.fromstring(extract_xml(raw))
    except ET.ParseError as exc:
        raise SDesktopError(f"invalid SDesktop XML: {exc}") from exc

    extensions: list[dict[str, object]] = []
    for hostscan in (node for node in root.iter() if _local_name(node.tag) == "hostscan"):
        for field in hostscan.iter():
            name = field.get("name", "")
            if _local_name(field.tag) != "field" or not name.startswith("cInspectorExtension"):
                continue
            value = field.get("value", "")
            parts = value.split("~")
            versions: dict[str, str] = {}
            if len(parts) > 1:
                match = re.search(
                    r"\bWin:([^,~]+),Mac:([^,~]+),Linux:([^,~]+)", parts[1]
                )
                if match:
                    versions = {
                        "windows": match.group(1),
                        "macos": match.group(2),
                        "linux": match.group(3),
                    }
            extensions.append({
                "name": name,
                "component": parts[0] if parts else "",
                "description": parts[1] if len(parts) > 1 else "",
                "versions": versions,
                "raw_value": value,
            })
    return extensions


def parse_profile(raw: bytes) -> list[PostureCheck]:
    """Load and validate an editable saved-check profile."""
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SDesktopError(f"invalid saved profile JSON: {exc}") from exc

    if isinstance(value, dict):
        if value.get("format") != PROFILE_FORMAT:
            raise SDesktopError(f"saved profile format must be {PROFILE_FORMAT!r}")
        records = value.get("checks")
    else:
        records = value
    if not isinstance(records, list):
        raise SDesktopError("saved profile must contain a checks array")

    checks: list[PostureCheck] = []
    seen: set[tuple[str, str, str]] = set()
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise SDesktopError(f"saved profile check {index} is not an object")
        raw_kind = record.get("kind")
        label = record.get("label")
        target = record.get("target")
        if not all(isinstance(item, str) and item.strip()
                   for item in (raw_kind, label, target)):
            raise SDesktopError(
                f"saved profile check {index} needs non-empty kind, label, and target strings"
            )
        kind = SUPPORTED_KINDS.get(raw_kind.casefold())
        if not kind:
            raise SDesktopError(f"saved profile check {index} has unsupported kind {raw_kind!r}")
        key = (kind, label, target)
        if key not in seen:
            checks.append(PostureCheck(*key))
            seen.add(key)
    return checks


def _load_profile_document(raw: bytes) -> dict[str, object]:
    """Load the complete saved profile document for fixture rendering."""
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SDesktopError(f"invalid saved profile JSON: {exc}") from exc

    if not isinstance(value, dict):
        raise SDesktopError("saved profile must be a JSON object")
    if value.get("format") != PROFILE_FORMAT:
        raise SDesktopError(f"saved profile format must be {PROFILE_FORMAT!r}")
    records = value.get("checks")
    if not isinstance(records, list):
        raise SDesktopError("saved profile must contain a checks array")
    return value


def save_profile(
    path: str,
    checks: Sequence[PostureCheck],
    source: str,
    inspector_extensions: Sequence[dict[str, object]] = (),
) -> None:
    """Write normalized checks as an editable JSON profile."""
    records = []
    for check in checks:
        record = asdict(check)
        expected: dict[str, object] = {"exists": True}
        if check.kind == "Process":
            expected["path"] = DEFAULT_EXPECTED_PROCESS_PATHS.get(
                _leaf_name(check.target).casefold(),
                "REPLACE",
            )
        if check.kind == "Registry":
            registry_value = DEFAULT_EXPECTED_REGISTRY_VALUES.get(check.target)
            if registry_value is None:
                if check.target.endswith(r"\Domain"):
                    registry_value = "corp.example"
                elif check.target.endswith(r"\ComputerName"):
                    registry_value = "EXAMPLE-HOST"
                else:
                    registry_value = ""
            expected.update({
                "type": "string",
                "value": registry_value,
            })
        if check.kind == "File":
            expected.update({
                "lastmodified": 0,
                "timestamp": 0,
                "crc32": "0x00000000",
            })
        record["expected"] = expected
        records.append(record)
    profile = {
        "format": PROFILE_FORMAT,
        "source": source,
        "inspector_extensions": list(inspector_extensions),
        "expected_endpoint": {
            "enforce": DEFAULT_EXPECTED_ENFORCE,
            "os": dict(DEFAULT_EXPECTED_OS),
            "device": dict(DEFAULT_EXPECTED_DEVICE),
            "am": json.loads(json.dumps(DEFAULT_EXPECTED_ANTIMALWARE)),
            "fw": json.loads(json.dumps(DEFAULT_EXPECTED_FIREWALL)),
        },
        "checks": records,
    }
    rendered = json.dumps(profile, indent=2, ensure_ascii=False) + "\n"
    if path == "-":
        sys.stdout.write(rendered)
    else:
        Path(path).write_text(rendered, encoding="utf-8")


def export_openconnect(profile_path: str, prefix: str | None = None) -> tuple[Path, Path]:
    """Generate an OpenConnect wrapper that submits explicit profile values."""
    profile = Path(profile_path).expanduser().resolve()
    parse_profile(profile.read_bytes())
    base = Path(prefix).expanduser().resolve() if prefix else profile.with_suffix("")
    wrapper = base.parent / f"{base.name}-openconnect.sh"
    config = base.parent / f"{base.name}-openconnect.conf"
    collector = Path(__file__).resolve()
    # Run through the interpreter so the wrapper works even if the script has
    # lost its executable bit (e.g. after a zip download).
    interpreter = shlex.quote(sys.executable or "python3")

    wrapper.write_text(
        "#!/bin/sh\n"
        "# Generated by cisco_profile_lens.py openconnect.\n"
        "set -eu\n"
        f"export SDESKTOP_PROFILE={shlex.quote(str(profile))}\n"
        "export SDESKTOP_PROFILE_MODE=fixture\n"
        "# Run by hand (not by OpenConnect): just show what would be submitted.\n"
        "if [ -z \"${CSD_HOSTNAME:-}\" ]; then\n"
        f"  exec {interpreter} {shlex.quote(str(collector))} preview \"$SDESKTOP_PROFILE\"\n"
        "fi\n"
        f"exec {interpreter} {shlex.quote(str(collector))} \"$@\"\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    config.write_text(
        "# Generated OpenConnect config fragment.\n"
        f"csd-wrapper={wrapper}\n",
        encoding="utf-8",
    )
    return wrapper, config


def build_http_preview(report: str, host: str) -> bytes:
    """Wrap a report as the raw scan.xml request, with a placeholder session
    token, for reading rather than replaying."""
    host = host.strip()
    if not host or any(char in host for char in "\r\n/?#@"):
        raise SDesktopError("--http needs a hostname or hostname:port")
    body = report.encode("utf-8")
    headers = (
        "POST /+CSCOE+/sdesktop/scan.xml?reusebrowser=1 HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Cookie: sdesktop=REPLACE_SESSION_TOKEN\r\n"
        "Content-Type: text/xml\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    ).encode("ascii")
    return headers + body


def _sdesktop_string(value: object) -> str:
    """Quote a value for Cisco's assignment format without doubling Windows paths."""
    text = str(value)
    escaped = (
        text
        .replace('"', r'\"')
        .replace("\r", r"\r")
        .replace("\n", r"\n")
        .replace("\t", r"\t")
    )
    return f'"{escaped}"'


def _js(value: object) -> str:
    """Retained for label formatting; Cisco's wire syntax is not JSON."""
    return _sdesktop_string(value)


def _assignment(name: str, value: object) -> str:
    return f"{name}={_js(value)};"


def _expected(record: dict[str, object], name: str, default: object) -> object:
    value = record.get("expected")
    if not isinstance(value, dict):
        return default
    return value.get(name, default)


def _fixture_value(value: object) -> object:
    if isinstance(value, bool):
        return str(value).lower()
    if value is None:
        return ""
    return value


def _leaf_name(target: str) -> str:
    # Posture targets are usually Windows paths; split on both separators on any host OS.
    return PureWindowsPath(target).name


def _expand_path(value: str) -> Path:
    # Expand both Unix $VAR syntax and Windows %VAR% syntax without a shell.
    value = re.sub(r"%([^%]+)%", lambda match: os.environ.get(match.group(1), match.group(0)), value)
    return Path(os.path.expanduser(os.path.expandvars(value)))


def _crc32(path: Path) -> int:
    checksum = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum = zlib.crc32(chunk, checksum)
    return checksum & 0xFFFFFFFF


def _running_processes() -> dict[str, str]:
    """Map case-folded executable basenames to the best known full path."""
    result: dict[str, str] = {}
    if os.name == "nt":
        powershell = (
            "$ErrorActionPreference='Stop'; "
            "ConvertTo-Json -Compress -InputObject "
            "@(Get-CimInstance Win32_Process | Select-Object Name,ExecutablePath)"
        )
        try:
            completed = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", powershell],
                check=True, capture_output=True, text=True, timeout=20,
            )
            records = json.loads(completed.stdout or "[]")
            if isinstance(records, dict):
                records = [records]
            for record in records:
                if not isinstance(record, dict):
                    continue
                name = str(record.get("Name") or "").strip()
                path = str(record.get("ExecutablePath") or name).strip()
                if name:
                    result.setdefault(name.casefold(), path or name)
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
            pass
        if result:
            return result

        try:
            completed = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"], check=True,
                capture_output=True, text=True, timeout=15,
            )
        except (OSError, subprocess.SubprocessError):
            completed = None
        if completed:
            try:
                for row in csv.reader(io.StringIO(completed.stdout)):
                    if row and row[0].strip():
                        name = row[0].strip()
                        result.setdefault(name.casefold(), name)
            except csv.Error:
                pass
        return result

    proc = Path("/proc")
    if proc.is_dir():
        for entry in proc.iterdir():
            if not entry.name.isdigit():
                continue
            candidates: list[str] = []
            try:
                candidates.append(os.readlink(entry / "exe"))
            except OSError:
                pass
            try:
                candidates.append((entry / "comm").read_text(errors="replace").strip())
            except OSError:
                pass
            for candidate in candidates:
                if candidate:
                    result.setdefault(Path(candidate).name.casefold(), candidate)

    if not result or platform.system() == "Darwin":
        try:
            completed = subprocess.run(
                ["ps", "-axo", "comm="], check=True, capture_output=True,
                text=True, timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            completed = None
        if completed:
            for line in completed.stdout.splitlines():
                candidate = line.strip()
                if candidate:
                    result.setdefault(Path(candidate).name.casefold(), candidate)
    return result


def _registry_value(target: str) -> tuple[bool, str, str]:
    """Read a Windows registry value, returning exists, type, value."""
    if os.name != "nt":
        return False, "", ""
    try:
        import winreg  # type: ignore[import-not-found]
    except ImportError:
        return False, "", ""

    roots = {
        "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
        "HKCR": winreg.HKEY_CLASSES_ROOT,
        "HKEY_USERS": winreg.HKEY_USERS,
        "HKU": winreg.HKEY_USERS,
    }
    parts = target.split("\\")
    if len(parts) < 3 or parts[0].upper() not in roots:
        return False, "", ""
    root = roots[parts[0].upper()]
    subkey, value_name = "\\".join(parts[1:-1]), parts[-1]
    try:
        with winreg.OpenKey(root, subkey) as key:
            value, value_type = winreg.QueryValueEx(key, value_name)
    except OSError:
        return False, "", ""
    type_names = {
        winreg.REG_DWORD: "dword",
        winreg.REG_QWORD: "dword",
        winreg.REG_SZ: "string",
        winreg.REG_EXPAND_SZ: "string",
        winreg.REG_MULTI_SZ: "string",
    }
    if isinstance(value, list):
        rendered = ";".join(str(item) for item in value)
    else:
        rendered = str(value)
    return True, type_names.get(value_type, "string"), rendered


def build_report(checks: Iterable[PostureCheck]) -> str:
    """Build the plaintext assignment report accepted by scan.xml."""
    lines = [
        _assignment("endpoint.os.version", platform.system()),
        _assignment("endpoint.os.servicepack", platform.release()),
        _assignment("endpoint.os.architecture", platform.machine()),
        _assignment("endpoint.policy.location", "Default"),
        _assignment("endpoint.device.hostname", socket.gethostname().split(".", 1)[0]),
    ]
    processes = _running_processes()

    for check in checks:
        label = _js(check.label)
        if check.kind == "Process":
            base = f"endpoint.process[{label}]"
            path = processes.get(_leaf_name(check.target).casefold())
            lines.extend([
                f"{base}={{}};",
                _assignment(f"{base}.name", check.target),
                _assignment(f"{base}.exists", str(bool(path)).lower()),
            ])
            if path:
                lines.append(_assignment(f"{base}.path", path))
        elif check.kind == "File":
            base = f"endpoint.file[{label}]"
            path = _expand_path(check.target)
            exists = path.is_file()
            lines.extend([
                f"{base}={{}};",
                _assignment(f"{base}.path", str(path)),
                _assignment(f"{base}.name", _leaf_name(str(path))),
                _assignment(f"{base}.exists", str(exists).lower()),
            ])
            if exists:
                stat = path.stat()
                lines.extend([
                    _assignment(f"{base}.lastmodified", max(0, int(time.time() - stat.st_mtime))),
                    _assignment(f"{base}.timestamp", int(stat.st_mtime)),
                    _assignment(f"{base}.crc32", f"0x{_crc32(path):08x}"),
                ])
        elif check.kind == "Registry":
            base = f"endpoint.registry[{label}]"
            exists, value_type, value = _registry_value(check.target)
            lines.extend([
                f"{base}={{}};",
                _assignment(f"{base}.exists", str(exists).lower()),
                _assignment(f"{base}.path", check.target),
            ])
            if exists:
                lines.extend([
                    _assignment(f"{base}.type", value_type),
                    _assignment(f"{base}.value", value),
                ])
    return "\n".join(lines) + "\n"


def build_fixture_report(profile: dict[str, object]) -> str:
    """Render a synthetic report from JSON placeholders for offline testing."""
    records = profile.get("checks")
    if not isinstance(records, list):
        raise SDesktopError("saved profile must contain a checks array")

    lines = [_assignment("endpoint.policy.location", "Default")]

    endpoint = profile.get("expected_endpoint")
    if isinstance(endpoint, dict):
        if "enforce" in endpoint:
            lines.append(_assignment("endpoint.enforce", _fixture_value(endpoint["enforce"])))
        os_expected = endpoint.get("os")
        if isinstance(os_expected, dict):
            for key in ("version", "servicepack", "architecture", "processor_level"):
                if key in os_expected:
                    lines.append(_assignment(f"endpoint.os.{key}", _fixture_value(os_expected[key])))
        device = endpoint.get("device")
        if isinstance(device, dict):
            for key in ("hostname", "id", "protection", "protection_version", "protection_extension"):
                if key in device:
                    lines.append(_assignment(f"endpoint.device.{key}", _fixture_value(device[key])))
            for key in ("port", "tcp4port", "udp4port", "tcp6port", "udp6port"):
                values = device.get(key)
                if not isinstance(values, dict):
                    continue
                for port, value in values.items():
                    if not isinstance(port, str) or not port.strip():
                        continue
                    lines.append(_assignment(
                        f"endpoint.device.{key}[{_js(port)}]",
                        _fixture_value(value),
                    ))
        antimalware = endpoint.get("am")
        if isinstance(antimalware, dict):
            for label, details in antimalware.items():
                if not isinstance(label, str) or not isinstance(details, dict):
                    continue
                base = f"endpoint.am[{_js(label)}]"
                lines.append(f"{base}={{}};")
                for key in ("exists", "description", "version", "activescan", "lastupdate", "timestamp"):
                    if key in details:
                        lines.append(_assignment(f"{base}.{key}", _fixture_value(details[key])))
        firewalls = endpoint.get("fw")
        if isinstance(firewalls, dict):
            for label, details in firewalls.items():
                if not isinstance(label, str) or not isinstance(details, dict):
                    continue
                base = f"endpoint.fw[{_js(label)}]"
                lines.append(f"{base}={{}};")
                for key in ("exists", "description", "version", "enabled"):
                    if key in details:
                        lines.append(_assignment(f"{base}.{key}", _fixture_value(details[key])))

    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise SDesktopError(f"saved profile check {index} is not an object")
        raw_kind = record.get("kind")
        label = record.get("label")
        target = record.get("target")
        if not all(isinstance(item, str) and item.strip()
                   for item in (raw_kind, label, target)):
            raise SDesktopError(
                f"saved profile check {index} needs non-empty kind, label, and target strings"
            )
        kind = SUPPORTED_KINDS.get(raw_kind.casefold())
        if not kind:
            raise SDesktopError(f"saved profile check {index} has unsupported kind {raw_kind!r}")

        key = _js(label)
        if kind == "Process":
            base = f"endpoint.process[{key}]"
            lines.extend([
                f"{base}={{}};",
                _assignment(f"{base}.name", target),
                _assignment(f"{base}.exists", str(bool(_expected(record, "exists", True))).lower()),
                _assignment(f"{base}.path", _fixture_value(_expected(record, "path", "REPLACE"))),
            ])
        elif kind == "File":
            base = f"endpoint.file[{key}]"
            lines.extend([
                f"{base}={{}};",
                _assignment(f"{base}.path", target),
                _assignment(f"{base}.name", _leaf_name(target)),
                _assignment(f"{base}.exists", str(bool(_expected(record, "exists", True))).lower()),
                _assignment(f"{base}.lastmodified", _fixture_value(_expected(record, "lastmodified", 0))),
                _assignment(f"{base}.timestamp", _fixture_value(_expected(record, "timestamp", 0))),
                _assignment(f"{base}.crc32", _fixture_value(_expected(record, "crc32", "REPLACE"))),
            ])
        elif kind == "Registry":
            base = f"endpoint.registry[{key}]"
            lines.extend([
                f"{base}={{}};",
                _assignment(f"{base}.exists", str(bool(_expected(record, "exists", True))).lower()),
                _assignment(f"{base}.path", target),
                _assignment(f"{base}.type", _fixture_value(_expected(record, "type", "string"))),
                _assignment(f"{base}.value", _fixture_value(_expected(record, "value", "REPLACE"))),
            ])
    return "\n".join(lines) + "\n"


def _curl_base() -> list[str]:
    command = [
        "curl", "--fail", "--silent", "--show-error",
        "--connect-timeout", "15", "--max-time", "60",
    ]
    tls_config = os.environ.get("SDESKTOP_TLS_CONFIG")
    if tls_config:
        command.extend(["--config", tls_config])
    if os.environ.get("SDESKTOP_SHOW_HTTP") == "1":
        command.extend(["--trace-ascii", "/dev/stderr"])
    pin = os.environ.get("CSD_SHA256")
    if pin:
        command.extend(["--insecure", "--pinnedpubkey", f"sha256//{pin}"])
    return command


def _curl(url: str, *, headers: Sequence[str] = (), data: bytes | None = None) -> bytes:
    command = _curl_base()
    for header in headers:
        command.extend(["--header", header])
    if data is not None:
        command.extend(["--header", "Expect:", "--data-binary", "@-"])
    command.append(url)
    try:
        completed = subprocess.run(
            command, input=data, check=True, capture_output=True, timeout=75,
        )
    except FileNotFoundError as exc:
        raise SDesktopError("curl is required but was not found in PATH") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode(errors="replace").strip()
        raise SDesktopError(f"curl failed for {url}: {detail or exc.returncode}") from exc
    except subprocess.TimeoutExpired as exc:
        raise SDesktopError(f"curl timed out for {url}") from exc
    if os.environ.get("SDESKTOP_SHOW_HTTP") == "1" and completed.stderr:
        print(completed.stderr.decode(errors="replace"), file=sys.stderr, end="")
    return completed.stdout


def _wrapper_options(args: Sequence[str]) -> dict[str, str]:
    options: dict[str, str] = {}
    index = 1  # argv[0] is OpenConnect's downloaded-stub filename (often empty)
    while index < len(args):
        item = args[index]
        if item.startswith("-") and index + 1 < len(args):
            options[item.lstrip("-")] = args[index + 1].strip('"')
            index += 2
        else:
            index += 1
    return options


def check_scan_response(raw: bytes) -> str:
    """Accept a successful submission, independently of eventual DAP authorization."""
    if re.search(br"<!\s*(?:DOCTYPE|ENTITY)\b", raw, re.IGNORECASE):
        raise SDesktopError("scan response contains a forbidden XML declaration")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise SDesktopError("scan response is empty or invalid XML") from exc
    statuses = [(node.text or "").strip() for node in root.iter()
                if _local_name(node.tag) == "status"]
    if _local_name(root.tag) != "hostscan" or len(statuses) != 1:
        raise SDesktopError("scan response must contain one hostscan status")
    status = statuses[0]
    if status not in {"TOKEN_SUCCESS", "TOKEN_LOGGEDON"}:
        raise SDesktopError(f"posture submission rejected: {status[:80] or 'empty status'}")
    return status


def run_wrapper(args: Sequence[str]) -> int:
    hostname = os.environ.get("CSD_HOSTNAME", "").strip()
    if not hostname or any(char in hostname for char in "/?#@"):
        raise SDesktopError("CSD_HOSTNAME is missing or invalid")
    options = _wrapper_options(args)
    ticket = options.get("ticket", "")
    stub = options.get("stub", "0")
    base = f"https://{hostname}"

    token = ""
    if ticket:
        query = urllib.parse.urlencode({"ticket": ticket, "stub": stub})
        token_xml = _curl(f"{base}/+CSCOE+/sdesktop/token.xml?{query}")
        try:
            token_root = ET.fromstring(extract_xml(token_xml))
            token = next(
                (node.text or "").strip() for node in token_root.iter()
                if _local_name(node.tag) == "token"
            )
        except (ET.ParseError, StopIteration) as exc:
            raise SDesktopError("token.xml did not contain a usable <token>") from exc
    if not token:
        token = os.environ.get("CSD_TOKEN", "").strip()
    if not token:
        raise SDesktopError("the server supplied neither a ticket nor CSD_TOKEN")

    profile_path = os.environ.get("SDESKTOP_PROFILE", "").strip()
    if profile_path:
        raw_profile = Path(profile_path).read_bytes()
        profile_mode = os.environ.get("SDESKTOP_PROFILE_MODE", "observed").strip().casefold()
        if profile_mode == "fixture":
            report = build_fixture_report(_load_profile_document(raw_profile)).encode()
            print(f"cisco-profile-lens: using saved profile values {profile_path}", file=sys.stderr)
        elif profile_mode == "observed":
            checks = parse_profile(raw_profile)
            report = build_report(checks).encode()
            print(f"cisco-profile-lens: using saved profile checks {profile_path}", file=sys.stderr)
        else:
            raise SDesktopError(
                "SDESKTOP_PROFILE_MODE must be 'observed' or 'fixture'"
            )
    else:
        data_xml = _curl(f"{base}/CACHE/sdesktop/data.xml")
        checks = parse_data_xml(data_xml)
        report = build_report(checks).encode()
    response = _curl(
        f"{base}/+CSCOE+/sdesktop/scan.xml?reusebrowser=1",
        headers=("Content-Type: text/xml", f"Cookie: sdesktop={token}"),
        data=report,
    )
    status = check_scan_response(response)
    print(f"cisco-profile-lens: {status}; submission acknowledged, VPN authorization is pending.",
          file=sys.stderr)
    return 0


def _is_url(value: str) -> bool:
    return urllib.parse.urlsplit(value).scheme.casefold() in {"http", "https"}


def data_xml_url(value: str) -> str:
    """Resolve a gateway base URL to its standard SDesktop data.xml path."""
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
        raise SDesktopError("input URL must be an absolute HTTP(S) URL")
    if parsed.path.casefold().endswith("/data.xml"):
        path = parsed.path
        query = parsed.query
    else:
        path = "/CACHE/sdesktop/data.xml"
        query = ""
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, query, ""))


def _read_input(source: str) -> bytes:
    if source == "-":
        return sys.stdin.buffer.read()
    if _is_url(source):
        url = data_xml_url(source)
        try:
            return _curl(url)
        except SDesktopError as exc:
            raise SDesktopError(f"no readable SDesktop data.xml at {url}: {exc}") from exc
    return Path(source).read_bytes()


def _print_checks(checks: Sequence[PostureCheck], extensions: Sequence[dict[str, object]]) -> None:
    """Readable table of the posture checks a gateway asks for."""
    if not checks:
        print("No File, Process or Registry checks in this policy.")
    else:
        width = max(len(check.label) for check in checks)
        print(f"{len(checks)} posture check(s):\n")
        print(f"  {'TYPE':<9} {'LABEL':<{width}}  TARGET")
        for check in checks:
            print(f"  {check.kind:<9} {check.label:<{width}}  {check.target}")
    if extensions:
        print(f"\n{len(extensions)} inspector extension(s):")
        for extension in extensions:
            print(f"  {extension['name']}: {extension['description'] or extension['component']}")


def _load_checks(raw: bytes) -> list[PostureCheck]:
    """Checks from data.xml, or from a saved profile."""
    if raw.lstrip().startswith((b"{", b"[")):
        return parse_profile(raw)
    return parse_data_xml(raw)


def _openconnect_host(profile: dict[str, object], override: str | None) -> str:
    if override:
        return override
    source = profile.get("source")
    if isinstance(source, str) and _is_url(source):
        return urllib.parse.urlsplit(source).netloc
    return "VPN_HOST"


COMMANDS = ("show", "save", "preview", "openconnect")


def _is_show_shorthand(argv: Sequence[str]) -> bool:
    # "<url>" or "<url> --json" (either order) is shorthand for "show <url> [--json]".
    urls = [arg for arg in argv if _is_url(arg)]
    return len(urls) == 1 and all(arg == "--json" for arg in argv if not _is_url(arg))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    commands = parser.add_subparsers(dest="command", required=True)

    show = commands.add_parser("show", help="list the posture checks in a data.xml")
    show.add_argument("input", help="gateway URL, data.xml file, or - for stdin")
    show.add_argument("--json", action="store_true", help="print the checks as JSON")

    save = commands.add_parser("save", help="write an editable profile")
    save.add_argument("input", help="gateway URL, data.xml file, or - for stdin")
    save.add_argument("output", help="profile JSON path, or - for stdout")

    preview = commands.add_parser("preview", help="print what would be submitted")
    preview.add_argument("profile", help="saved profile JSON path")
    preview.add_argument(
        "--observed", action="store_true",
        help="evaluate the profile's checks on this machine instead of using its values",
    )
    preview.add_argument(
        "--http", metavar="HOST",
        help="show the raw scan.xml request for HOST (placeholder session token)",
    )

    openconnect = commands.add_parser(
        "openconnect", help="write an OpenConnect wrapper that submits the profile"
    )
    openconnect.add_argument("profile", help="saved profile JSON path")
    openconnect.add_argument("--host", help="VPN hostname for the printed command")
    openconnect.add_argument(
        "--prefix", help="output path prefix (default: profile name without .json)"
    )
    return parser


def cli(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if _is_show_shorthand(argv):
        argv = ["show", *argv]
    if os.environ.get("CSD_HOSTNAME") and (not argv or argv[0] not in COMMANDS):
        return run_wrapper(argv)  # started by OpenConnect as its CSD wrapper
    if not argv or argv[0] in {"-h", "--help"}:
        _build_parser().print_help()
        return 0
    if argv[0] not in COMMANDS:
        raise SDesktopError(
            f"unknown command {argv[0]!r}; expected one of: {', '.join(COMMANDS)}"
        )

    options = _build_parser().parse_args(argv)

    if options.command == "show":
        raw = _read_input(options.input)
        checks = _load_checks(raw)
        if options.json:
            json.dump([asdict(check) for check in checks], sys.stdout, indent=2)
            sys.stdout.write("\n")
        else:
            is_profile = raw.lstrip().startswith((b"{", b"["))
            _print_checks(checks, [] if is_profile else parse_inspector_extensions(raw))
        return 0

    if options.command == "save":
        raw = _read_input(options.input)
        save_profile(
            options.output, parse_data_xml(raw), options.input,
            parse_inspector_extensions(raw),
        )
        if options.output != "-":
            print(f"Wrote {Path(options.output).resolve()}. Edit the expected values, then run:")
            print(f"  {Path(sys.argv[0]).name} preview {options.output}")
        return 0

    raw_profile = Path(options.profile).read_bytes()
    profile = _load_profile_document(raw_profile)

    if options.command == "preview":
        if options.observed:
            report = build_report(parse_profile(raw_profile))
        else:
            report = build_fixture_report(profile)
        if options.http:
            sys.stdout.buffer.write(build_http_preview(report, options.http))
        else:
            sys.stdout.write(report)
        return 0

    wrapper, config = export_openconnect(options.profile, options.prefix)
    host = _openconnect_host(profile, options.host)
    print(f"Wrote {wrapper}")
    print(f"Wrote {config}")
    print("\nConnect with:")
    print(f"  sudo openconnect --protocol=anyconnect --config={shlex.quote(str(config))} {host}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(cli())
    except (OSError, SDesktopError) as exc:
        print(f"cisco-profile-lens: {exc}", file=sys.stderr)
        raise SystemExit(1)
