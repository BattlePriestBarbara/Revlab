"""Builders for synthetic samples: a safe target that needs no third party.

These generate *structurally valid* inputs -- a real Android binary XML document,
a real ELF shared object, a real APK zip -- which is what makes them worth
something: the parsers run against data laid out the way the real toolchain lays
it out, not against hand-written dictionaries.

They ship in the package rather than in the test suite because the desktop app
offers a "make me a target" button: the first run of a reverse-engineering tool
should not require the operator to already own a suspicious binary, and a
committed sample built from these builders is reproducible and carries no
licensing question.

Each builder returns ``bytes`` and writes to ``path`` when one is given, so the
same function serves a unit test (keep it in memory) and the UI (drop it on
disk). :func:`build_demo_apk` is the one the UI calls: an APK whose interesting
properties are known in advance -- an encrypted DEX body, a high-entropy asset,
two native libraries, a debuggable manifest.
"""

from __future__ import annotations

import random
import struct
import zipfile
from pathlib import Path

RES_STRING_POOL = 0x0001
RES_XML_START_ELEMENT = 0x0102
TYPE_STRING, TYPE_INT_DEC, TYPE_INT_BOOLEAN = 0x03, 0x10, 0x12
_NDK_BANNER = "Android (12418516, +pgo, +bolt, +lto, +mlgo) clang version 14.0.7"


# ---- Android binary XML ----------------------------------------------------
def _string_pool(strings: list[str]) -> bytes:
    offsets: list[int] = []
    blob = b""
    for text in strings:
        offsets.append(len(blob))
        blob += struct.pack("<H", len(text)) + text.encode("utf-16-le") + b"\x00\x00"
    offset_table = b"".join(struct.pack("<I", value) for value in offsets)
    header_size = 28
    strings_start = header_size + len(offset_table)
    chunk_size = strings_start + len(blob)
    header = struct.pack(
        "<HHIIIIII",
        RES_STRING_POOL, header_size, chunk_size, len(strings), 0, 0, strings_start, 0,
    )
    return header + offset_table + blob


def _start_element(name_idx: int, attributes: list[tuple]) -> bytes:
    """One start-element chunk; attributes are (name_idx, raw_idx, type_id, data)."""
    body = struct.pack("<II", 0xFFFFFFFF, name_idx)
    body += struct.pack("<HHHHHH", 20, 20, len(attributes), 0, 0, 0)
    for name, raw, type_id, data in attributes:
        body += struct.pack("<IIIHBB", 0xFFFFFFFF, name, raw, 8, 0, type_id)
        body += struct.pack("<I", data)
    size = 16 + len(body)
    return struct.pack("<HHIII", RES_XML_START_ELEMENT, 16, size, 1, 0xFFFFFFFF) + body


def build_axml(strings: list[str], elements: list[tuple[int, list[tuple]]]) -> bytes:
    """Assemble a complete AXML document from (name_idx, attributes) elements."""
    pool = _string_pool(strings)
    for name_idx, attributes in elements:
        if name_idx >= len(strings):
            raise ValueError("element name index out of range")
        for attr_name, raw, _type_id, _data in attributes:
            for index in (attr_name, raw):
                if index != 0xFFFFFFFF and index >= len(strings):
                    raise ValueError("attribute index out of range")
    chunks = b"".join(_start_element(name_idx, attrs) for name_idx, attrs in elements)
    total = 8 + len(pool) + len(chunks)
    return struct.pack("<HHI", 0x0003, 8, total) + pool + chunks


def _attr(index: dict, name: str, value, type_id: int = TYPE_STRING) -> tuple:
    if type_id == TYPE_STRING:
        return (index[name], index[str(value)], type_id, index[str(value)])
    return (index[name], 0xFFFFFFFF, type_id, value)


_MANIFEST_STRINGS = [
    "manifest", "package", "versionCode", "versionName",
    "uses-sdk", "minSdkVersion", "targetSdkVersion",
    "application", "name", "debuggable", "usesCleartextTraffic", "extractNativeLibs",
    "uses-permission", "activity",
    "com.example.demo", "1.4.2", "DemoApplication", "com.example.demo.MainActivity",
    "android.permission.SYSTEM_ALERT_WINDOW",
]


def build_manifest_axml(package: str = "com.example.demo") -> bytes:
    """A manifest with exactly the fields the heuristics care about."""
    strings = list(_MANIFEST_STRINGS)
    index = {text: position for position, text in enumerate(strings)}
    elements = [
        (index["manifest"], [
            _attr(index, "package", package),
            _attr(index, "versionCode", 7, TYPE_INT_DEC),
            _attr(index, "versionName", "1.4.2"),
        ]),
        (index["uses-sdk"], [
            _attr(index, "minSdkVersion", 24, TYPE_INT_DEC),
            _attr(index, "targetSdkVersion", 34, TYPE_INT_DEC),
        ]),
        (index["application"], [
            _attr(index, "name", "DemoApplication"),
            _attr(index, "debuggable", 1, TYPE_INT_BOOLEAN),
            _attr(index, "usesCleartextTraffic", 1, TYPE_INT_BOOLEAN),
            _attr(index, "extractNativeLibs", 0, TYPE_INT_BOOLEAN),
        ]),
        (index["uses-permission"], [
            _attr(index, "name", "android.permission.SYSTEM_ALERT_WINDOW"),
        ]),
        (index["activity"], [_attr(index, "name", "com.example.demo.MainActivity")]),
    ]
    return build_axml(strings, elements)


# ---- DEX -------------------------------------------------------------------
def plain_dex_blob(method_ids: int = 64, class_defs: int = 4, size: int = 4096) -> bytes:
    """A DEX whose header is consistent and whose body is low-entropy."""
    blob = bytearray(size)
    blob[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", blob, 32, size)      # file_size
    struct.pack_into("<I", blob, 36, 112)       # header_size
    struct.pack_into("<I", blob, 56, 512)       # string_ids_size
    struct.pack_into("<I", blob, 64, 128)       # type_ids_size
    struct.pack_into("<I", blob, 88, method_ids)  # method_ids_size
    struct.pack_into("<I", blob, 96, class_defs)  # class_defs_size
    for position in range(112, size):
        blob[position] = position % 97
    return bytes(blob)


def encrypted_dex_blob(size: int = 1 << 19, declared: int = 12 << 20) -> bytes:
    """DEX magic followed by ciphertext, with a file_size that does not match."""
    blob = bytearray(b"dex\n035\x00" + random_blob(size - 8))
    struct.pack_into("<I", blob, 32, declared)
    struct.pack_into("<I", blob, 36, 112)
    return bytes(blob)


def random_blob(size: int, seed: int = 1337) -> bytes:
    generator = random.Random(seed)
    return bytes(generator.randrange(256) for _ in range(size))


# ---- APK -------------------------------------------------------------------
def build_manifest_apk(path: Path, package: str = "com.example.demo") -> Path:
    """Minimal but valid APK: manifest, two DEX files, one native lib, one asset."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", build_manifest_axml(package))
        archive.writestr("classes.dex", encrypted_dex_blob())
        archive.writestr("classes2.dex", plain_dex_blob(method_ids=128, class_defs=8))
        archive.writestr("lib/x86_64/libfoo.so", build_elf(banner=_NDK_BANNER))
        archive.writestr("lib/arm64-v8a/libfoo.so", build_elf(banner=_NDK_BANNER))
        archive.writestr("assets/payload.bin", random_blob(1 << 20))
        archive.writestr("resources.arsc", b"\x02\x00\x0c\x00" + bytes(64))
    return path


# ---- ELF -------------------------------------------------------------------
def _section(name: int, type_id: int, offset: int, size: int, link: int,
             entsize: int) -> bytes:
    return struct.pack(
        "<IIQQQQIIQQ", name, type_id, 0, 0, offset, size, link, 0, 8, entsize
    )


def build_elf(path: Path | None = None, banner: str = _NDK_BANNER,
              soname: str = "libfoo.so",
              needed: tuple[str, ...] = ("libc.so", "liblog.so"),
              exports: tuple[str, ...] = (), with_symtab: bool = False) -> bytes:
    """Build a structurally valid ELF64 shared object (vaddr == file offset).

    The single PT_LOAD segment maps the whole file at virtual address 0, so
    DT_STRTAB can point straight at the .dynstr file offset -- which exercises
    the parser's vaddr -> file offset path exactly the way a real loader would.
    """
    dynstr = bytearray(b"\x00")

    def add_string(text: str, pool: bytearray) -> int:
        offset = len(pool)
        pool.extend(text.encode("ascii") + b"\x00")
        return offset

    soname_offset = add_string(soname, dynstr)
    needed_offsets = [add_string(name, dynstr) for name in needed]
    export_offsets = [add_string(name, dynstr) for name in exports]

    symtab = bytearray(bytes(24))  # null symbol always comes first
    for offset in export_offsets:
        symtab.extend(struct.pack("<IBBHQQ", offset, 0x12, 0, 1, 0x1000 + offset, 32))

    symtab_section = bytearray()
    if with_symtab:
        symtab_section.extend(bytes(24))
        symtab_section.extend(struct.pack("<IBBHQQ", soname_offset, 0x12, 0, 1, 0x2000, 16))

    shstrtab = bytearray(b"\x00")
    name_dynstr = add_string(".dynstr", shstrtab)
    name_dynsym = add_string(".dynsym", shstrtab)
    name_symtab = add_string(".symtab", shstrtab)
    name_comment = add_string(".comment", shstrtab)
    name_shstrtab = add_string(".shstrtab", shstrtab)

    comment = banner.encode("utf-8") + b"\x00"
    ehsize, phentsize, shentsize = 64, 56, 64
    phnum = 2
    phoff = ehsize
    dynstr_off = phoff + phnum * phentsize
    dynsym_off = dynstr_off + len(dynstr)
    symtab_off = dynsym_off + len(symtab)
    comment_off = symtab_off + len(symtab_section)
    shstrtab_off = comment_off + len(comment)

    sections = [
        (0, 0, 0, 0, 0, 0),                                        # SHT_NULL
        (name_dynstr, 3, dynstr_off, len(dynstr), 0, 0),            # SHT_STRTAB
        (name_dynsym, 11, dynsym_off, len(symtab), 1, 24),          # SHT_DYNSYM
        (name_comment, 1, comment_off, len(comment), 0, 0),         # SHT_PROGBITS
        (name_shstrtab, 3, shstrtab_off, len(shstrtab), 0, 0),      # SHT_STRTAB
    ]
    if with_symtab:
        sections.insert(4, (name_symtab, 2, symtab_off, len(symtab_section), 1, 24))

    shoff = (shstrtab_off + len(shstrtab) + 7) & ~7
    dyn_off = shoff + len(sections) * shentsize
    dynamic = [(14, soname_offset)]                       # DT_SONAME
    dynamic += [(1, offset) for offset in needed_offsets]  # DT_NEEDED
    dynamic += [(5, dynstr_off), (10, len(dynstr)), (0, 0)]
    dyn_size = len(dynamic) * 16
    total = dyn_off + dyn_size

    header = bytearray(ehsize)
    header[0:4] = b"\x7fELF"
    header[4:6] = bytes((2, 1))                           # 64-bit, little endian
    struct.pack_into("<HHI", header, 16, 3, 62, 1)        # ET_DYN, EM_X86_64
    struct.pack_into("<Q", header, 24, 0x1000)            # e_entry
    struct.pack_into("<Q", header, 32, phoff)
    struct.pack_into("<Q", header, 40, shoff)
    struct.pack_into("<H", header, 52, ehsize)
    struct.pack_into("<H", header, 54, phentsize)
    struct.pack_into("<H", header, 56, phnum)
    struct.pack_into("<H", header, 58, shentsize)
    struct.pack_into("<H", header, 60, len(sections))
    shstrndx = next(
        position for position, entry in enumerate(sections) if entry[0] == name_shstrtab
    )
    struct.pack_into("<H", header, 62, shstrndx)

    load = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, total, total, 0x1000)
    dynamic_segment = struct.pack("<IIQQQQQQ", 2, 6, dyn_off, 0, 0, dyn_size, dyn_size, 8)
    section_table = b"".join(_section(*entry) for entry in sections)
    dynamic_blob = b"".join(struct.pack("<QQ", tag, value) for tag, value in dynamic)

    blob = (
        bytes(header) + load + dynamic_segment
        + bytes(dynstr) + bytes(symtab) + bytes(symtab_section) + comment + bytes(shstrtab)
    )
    blob += b"\x00" * (shoff - len(blob))
    blob += section_table + dynamic_blob
    assert len(blob) == total, (len(blob), total)
    if path is not None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_bytes(blob)
    return blob


# ---- what the desktop app's "generate a target" button calls ----------------
#: Package name baked into the synthetic sample; also the string the operator can
#: put into ``[scope] authorised`` when they want to run Frida against it.
DEMO_PACKAGE = "com.example.demo"


def build_demo_apk(path: Path | str) -> Path:
    """Write the synthetic APK and return where it landed.

    The properties are fixed and known, which is the point: triage on this file
    must report an encrypted DEX body, a high-entropy asset, two native
    libraries, a debuggable manifest and cleartext traffic. If it stops doing
    that, the sample changed or the heuristics did.
    """
    return build_manifest_apk(Path(path), package=DEMO_PACKAGE)
