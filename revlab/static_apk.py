"""APK triage: ZIP inventory, entropy, DEX headers and AndroidManifest (AXML).

The first pass over an unknown APK must answer four questions without Ghidra,
Frida or a device:

1. what is in the archive, and what looks suspiciously stored/high-entropy;
2. which DEX files are real -- a DEX header claims ``file_size`` (12 MB, say)
   but if the magic is followed by noise, that file is an encrypted payload,
   not code;
3. which native libraries exist, for which ABIs, and what they look like
   (:mod:`revlab.elf`);
4. what the manifest says: package name, Application class, SDK levels,
   ``extractNativeLibs`` and permissions. That is also what makes the later
   Frida step possible at all.

Standard library only.
"""

from __future__ import annotations

import fnmatch
import hashlib
import math
import re
import struct
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import elf

# ---- Android binary XML (AXML) --------------------------------------------
RES_STRING_POOL, RES_XML_START_ELEMENT = 0x0001, 0x0102
TYPE_STRING, TYPE_INT_DEC, TYPE_INT_HEX, TYPE_INT_BOOLEAN = 0x03, 0x10, 0x11, 0x12
UTF8_FLAG = 0x100
DEX_MAGIC = b"dex\n"


@dataclass
class ApkManifest:
    package: str = ""
    version_name: str = ""
    version_code: int = 0
    min_sdk: int = 0
    target_sdk: int = 0
    application_class: str = ""
    debuggable: bool = False
    extract_native_libs: bool = True
    uses_clear_text_traffic: bool | None = None
    permissions: list[str] = field(default_factory=list)
    components: dict[str, list[str]] = field(default_factory=dict)
    parse_error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _string_pool(data: bytes, offset: int) -> tuple[list[str], int]:
    """Decode a resource string pool chunk; returns (strings, chunk_end)."""
    _, _, chunk_size = struct.unpack_from("<HHI", data, offset)
    string_count, _, flags = struct.unpack_from("<III", data, offset + 8)
    strings_start = struct.unpack_from("<I", data, offset + 20)[0]
    offsets = struct.unpack_from(f"<{string_count}I", data, offset + 28)
    base = offset + strings_start
    utf8 = bool(flags & UTF8_FLAG)

    strings: list[str] = []
    for string_offset in offsets:
        cursor = base + string_offset
        if cursor >= len(data):
            strings.append("")
            continue
        try:
            if utf8:
                # UTF-8 pools: two (possibly two-byte) lengths, then the bytes.
                char_len = data[cursor]
                cursor += 1
                if char_len & 0x80:
                    char_len = ((char_len & 0x7F) << 8) | data[cursor]
                    cursor += 1
                byte_len = data[cursor]
                cursor += 1
                if byte_len & 0x80:
                    byte_len = ((byte_len & 0x7F) << 8) | data[cursor]
                    cursor += 1
                strings.append(data[cursor : cursor + byte_len].decode("utf-8", "replace"))
            else:
                length = struct.unpack_from("<H", data, cursor)[0]
                cursor += 2
                if length & 0x8000:
                    length = ((length & 0x7FFF) << 16) | struct.unpack_from("<H", data, cursor)[0]
                    cursor += 2
                strings.append(
                    data[cursor : cursor + length * 2].decode("utf-16-le", "replace")
                )
        except (IndexError, struct.error, UnicodeDecodeError):
            strings.append("")
    return strings, offset + chunk_size


def parse_axml(data: bytes) -> tuple[list[dict], list[str]]:
    """Return (elements, strings) for an AXML document.

    Elements are ``{"name": str, "attrs": {name: value}}`` with values already
    resolved through the string pool. Nesting is flattened: Android's manifest
    semantics do not need the tree, and a flat list is easier to query.
    """
    if len(data) < 8 or struct.unpack_from("<H", data, 0)[0] != 0x0003:
        raise ValueError("not an Android binary XML document")

    strings: list[str] = []
    elements: list[dict] = []
    cursor = 8
    while cursor + 8 <= len(data):
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, cursor)
        if chunk_size < 8 or cursor + chunk_size > len(data):
            break
        if chunk_type == RES_STRING_POOL and not strings:
            strings, _ = _string_pool(data, cursor)
        elif chunk_type == RES_XML_START_ELEMENT:
            # Layout: 16-byte node header, then ns(4) name(4) attributeStart(2)
            # attributeSize(2) attributeCount(2) id(2) class(2) style(2), then
            # attributeCount * 20-byte attributes.
            body = cursor + header_size
            name_idx = struct.unpack_from("<I", data, body + 4)[0]
            attr_count = struct.unpack_from("<H", data, body + 12)[0]
            attrs: dict[str, str | int | bool] = {}
            attr_cursor = body + 20
            for _ in range(attr_count):
                if attr_cursor + 20 > len(data):
                    break
                _, attr_name_idx, raw_idx = struct.unpack_from("<III", data, attr_cursor)
                type_id = data[attr_cursor + 15]
                data_value = struct.unpack_from("<I", data, attr_cursor + 16)[0]
                name = (
                    strings[attr_name_idx]
                    if attr_name_idx < len(strings)
                    else f"attr{attr_name_idx}"
                )
                if raw_idx != 0xFFFFFFFF:
                    value: str | int | bool = (
                        strings[raw_idx] if raw_idx < len(strings) else ""
                    )
                elif type_id == TYPE_STRING:
                    value = strings[data_value] if data_value < len(strings) else ""
                elif type_id in (TYPE_INT_DEC, TYPE_INT_HEX):
                    value = data_value
                elif type_id == TYPE_INT_BOOLEAN:
                    value = bool(data_value)
                else:
                    value = data_value
                attrs[name] = value
                attr_cursor += 20
            elements.append(
                {
                    "name": strings[name_idx] if name_idx < len(strings) else "?",
                    "attrs": attrs,
                }
            )
        cursor += chunk_size
    return elements, strings


def _first_attr(elements: list[dict], element: str, attr: str):
    for item in elements:
        if item["name"] == element and attr in item["attrs"]:
            return item["attrs"][attr]
    return None


def read_manifest(path: str | Path, member: str = "AndroidManifest.xml") -> ApkManifest:
    """Parse AndroidManifest.xml from an APK (or from a raw AXML file)."""
    manifest = ApkManifest()
    try:
        target = Path(path)
        if target.suffix.lower() == ".xml":
            blob = target.read_bytes()
        else:
            with zipfile.ZipFile(target) as archive:
                blob = archive.read(member)
        elements, _ = parse_axml(blob)
    except (KeyError, OSError, ValueError, zipfile.BadZipFile, struct.error) as exc:
        manifest.parse_error = f"{type(exc).__name__}: {exc}"
        return manifest

    manifest.package = str(_first_attr(elements, "manifest", "package") or "")
    version_code = _first_attr(elements, "manifest", "versionCode")
    manifest.version_code = int(version_code) if isinstance(version_code, int) else 0
    manifest.version_name = str(_first_attr(elements, "manifest", "versionName") or "")

    uses_sdk = next((e for e in elements if e["name"] == "uses-sdk"), None)
    if uses_sdk:
        manifest.min_sdk = int(uses_sdk["attrs"].get("minSdkVersion", 0) or 0)
        manifest.target_sdk = int(uses_sdk["attrs"].get("targetSdkVersion", 0) or 0)

    application = next((e for e in elements if e["name"] == "application"), None)
    if application:
        attrs = application["attrs"]
        manifest.application_class = str(attrs.get("name", "") or "")
        manifest.debuggable = bool(attrs.get("debuggable", False))
        if "extractNativeLibs" in attrs:
            manifest.extract_native_libs = bool(attrs["extractNativeLibs"])
        if "usesCleartextTraffic" in attrs:
            manifest.uses_clear_text_traffic = bool(attrs["usesCleartextTraffic"])

    for item in elements:
        if item["name"] == "uses-permission":
            permission = item["attrs"].get("name")
            if permission:
                manifest.permissions.append(str(permission))
        elif item["name"] in ("activity", "service", "receiver", "provider"):
            component = item["attrs"].get("name")
            if component:
                manifest.components.setdefault(item["name"], []).append(str(component))
    return manifest


# ---- archive / DEX inventory ----------------------------------------------
SAMPLE_LIMIT = 1 << 20  # 1 MiB is plenty to tell code from ciphertext


def shannon_entropy(blob: bytes) -> float:
    """Entropy in bits/byte: ~8.0 means indistinguishable from random data."""
    if not blob:
        return 0.0
    counts = [0] * 256
    for byte in blob:
        counts[byte] += 1
    total = len(blob)
    return round(
        -sum((c / total) * math.log2(c / total) for c in counts if c), 4
    )


def sha256_file(path: str | Path, limit: int | None = None) -> str:
    digest = hashlib.sha256()
    read = 0
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(1 << 20)
            if not chunk:
                break
            digest.update(chunk)
            read += len(chunk)
            if limit is not None and read >= limit:
                break
    return digest.hexdigest()


def sha256_bytes(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def _sample(archive: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    with archive.open(info) as handle:
        return handle.read(limit)


def extract_members(apk: str | Path, patterns: tuple[str, ...], dest: Path,
                    single_member: str | None = None,
                    max_entry: int = 256 << 20) -> list[Path]:
    """Extract selected archive members into *dest*, refusing unsafe names.

    Path traversal is the one thing an analysis tool must never do while
    unpacking a hostile sample, so names containing ``..`` or a root/drive
    prefix are skipped instead of being silently sanitised.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    with zipfile.ZipFile(apk) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            if single_member is not None:
                if info.filename != single_member:
                    continue
            elif not any(fnmatch.fnmatch(info.filename, pattern) for pattern in patterns):
                continue
            if info.file_size > max_entry:
                continue
            if Path(info.filename).is_absolute() or ".." in Path(info.filename).parts:
                continue
            target = dest / Path(*Path(info.filename).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, target.open("wb") as sink:
                while True:
                    chunk = source.read(1 << 20)
                    if not chunk:
                        break
                    sink.write(chunk)
            written.append(target)
    return written


DEX_PATTERN = re.compile(r".*classes\d*\.dex$", re.IGNORECASE)
NATIVE_LIB_PATTERN = re.compile(r"^lib/(?P<abi>[^/]+)/(?P<name>[^/]+\.so)$", re.IGNORECASE)


def probe_apk(path: str | Path, sample_limit: int = SAMPLE_LIMIT) -> dict:
    """Everything the first pass should know about an APK, as plain JSON data."""
    target = Path(path)
    report: dict = {
        "file": {
            "path": str(target),
            "name": target.name,
            "size": target.stat().st_size if target.exists() else 0,
            "sha256": sha256_file(target) if target.exists() else "",
        },
        "manifest": {},
        "entries": [],
        "by_extension": {},
        "dex": [],
        "native_libs": [],
        "abis": {},
        "assets": {"count": 0, "bytes": 0, "largest": []},
        "flags": {},
        "error": None,
    }
    if not target.exists():
        report["error"] = "file does not exist"
        return report

    try:
        archive = zipfile.ZipFile(target)
    except (zipfile.BadZipFile, OSError) as exc:
        # Naming the format turns "triage failed" into the next command to run:
        # an operator who grabbed a Windows build instead of an APK, or a .so
        # instead of the package that wraps it, is told what they are holding.
        kind = elf.sniff(target)
        if kind == "zip":
            report["error"] = (
                f"zip container is unreadable: {exc}; if this is an APK, re-copy it -- "
                "a truncated download is the usual cause"
            )
        elif kind == "elf":
            report["error"] = (
                f"not an APK: {target.name} is a native ELF object; "
                "`revlab elf <path>` or `revlab ghidra summary <path>` reads it"
            )
        elif kind == "pe":
            report["error"] = (
                f"not an APK: {target.name} is Windows PE/COFF; "
                "`revlab ghidra summary <path>` reads it directly"
            )
        else:
            report["error"] = (
                f"not an APK (detected {kind}): {exc}; "
                "`revlab elf <file>` and `revlab ghidra summary <file>` cover other formats"
            )
        return report

    with archive:
        infos = archive.infolist()
        assets: list[tuple[int, str]] = []
        for info in infos:
            if info.is_dir():
                continue
            entropy = 0.0
            if info.file_size >= 4096:
                try:
                    entropy = shannon_entropy(_sample(archive, info, sample_limit))
                except (OSError, zipfile.BadZipFile, RuntimeError):
                    entropy = 0.0
            suffix = Path(info.filename).suffix.lower() or "<none>"
            report["by_extension"][suffix] = report["by_extension"].get(suffix, 0) + 1
            report["entries"].append(
                {
                    "name": info.filename,
                    "size": info.file_size,
                    "compressed": info.compress_size,
                    "method": "store" if info.compress_type == zipfile.ZIP_STORED else "deflate",
                    "ratio": round(info.compress_size / info.file_size, 4) if info.file_size else 0.0,
                    "entropy": entropy,
                }
            )
            if info.filename.startswith("assets/"):
                assets.append((info.file_size, info.filename))

            if DEX_PATTERN.match(info.filename):
                try:
                    blob = _sample(archive, info, 64 << 20)
                    dex = inspect_dex(info.filename, blob)
                    dex.size = info.file_size
                    report["dex"].append(dex.to_dict())
                except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
                    report["dex"].append({"name": info.filename, "note": f"unreadable: {exc}"})

            match = NATIVE_LIB_PATTERN.match(info.filename)
            if match:
                try:
                    blob = _sample(archive, info, 128 << 20)
                except (OSError, zipfile.BadZipFile, RuntimeError):
                    blob = b""
                abi = match.group("abi")
                report["abis"][abi] = report["abis"].get(abi, 0) + 1
                report["native_libs"].append(
                    {
                        "name": match.group("name"),
                        "member": info.filename,
                        "abi": abi,
                        "size": info.file_size,
                        "entropy": shannon_entropy(blob[:sample_limit]) if blob else 0.0,
                        "sha256": sha256_bytes(blob) if blob else "",
                    }
                )

        report["manifest"] = read_manifest(target).to_dict()

        assets.sort(reverse=True)
        report["assets"] = {
            "count": len(assets),
            "bytes": sum(size for size, _ in assets),
            "largest": [{"name": name, "size": size} for size, name in assets[:10]],
        }
        report["flags"] = _apk_flags(report, target, infos)
        report["entries"].sort(key=lambda item: -item["size"])
    return report


def _apk_flags(report: dict, target: Path, infos: list[zipfile.ZipInfo]) -> dict:
    """Cheap booleans that decide which analysis route is worth trying."""
    names = [info.filename for info in infos]
    size = target.stat().st_size
    with target.open("rb") as handle:
        handle.seek(max(0, size - 4096))
        tail = handle.read()
    return {
        "multiple_dex": len(report["dex"]) > 1,
        "encrypted_dex": any(dex.get("looks_encrypted") for dex in report["dex"]),
        "has_native_libs": bool(report["native_libs"]),
        "abis": sorted(report["abis"]),
        "has_resources_arsc": "resources.arsc" in names,
        "v2_signature_block": b"APK Sig Block 42" in tail,
        "v1_signature": any(
            name.startswith("META-INF/") and name.upper().endswith(".SF") for name in names
        ),
        "has_kotlin_metadata": any(name.endswith(".kotlin_module") for name in names),
        "asset_bytes": report["assets"]["bytes"],
    }


@dataclass
class DexInfo:
    name: str
    size: int
    declared_size: int = 0
    version: str = ""
    string_ids: int = 0
    type_ids: int = 0
    method_ids: int = 0
    class_defs: int = 0
    entropy: float = 0.0
    looks_encrypted: bool = False
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def inspect_dex(name: str, blob: bytes) -> DexInfo:
    """Read a DEX header and decide whether the body is plausibly code."""
    info = DexInfo(name=name, size=len(blob))
    if len(blob) < 112 or not blob.startswith(DEX_MAGIC):
        info.note = "not a DEX file (missing magic)"
        info.entropy = shannon_entropy(blob[:SAMPLE_LIMIT])
        return info

    info.version = blob[4:7].decode("ascii", "replace")
    try:
        (declared,) = struct.unpack_from("<I", blob, 32)
        (info.string_ids,) = struct.unpack_from("<I", blob, 56)
        (info.type_ids,) = struct.unpack_from("<I", blob, 64)
        (info.method_ids,) = struct.unpack_from("<I", blob, 88)
        (info.class_defs,) = struct.unpack_from("<I", blob, 96)
    except struct.error:
        info.note = "truncated DEX header"
        return info

    info.declared_size = declared
    body = blob[112 : 112 + SAMPLE_LIMIT]
    info.entropy = shannon_entropy(body)

    if declared and declared != len(blob):
        info.looks_encrypted = True
        info.note = f"declared file_size={declared} but entry holds {len(blob)} bytes"
    elif info.class_defs == 0 and info.size > (1 << 20):
        info.looks_encrypted = True
        info.note = "no class_defs but a multi-megabyte body"
    elif info.entropy >= 7.5:
        info.looks_encrypted = True
        info.note = f"body entropy {info.entropy} bits/byte (ciphertext-like)"
    return info
