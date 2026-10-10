"""Draw the RevLab icon and write it out as .ico / .png -- standard library only.

An installer, a shortcut and an Android launcher all want an image, and adding
Pillow to a project whose selling point is "no dependencies" would be silly. A
32-bit RGBA raster and a PNG encoder are about sixty lines of ``zlib`` and
``struct``; the drawing happens at 2-4x and is box-filtered down, which is
enough anti-aliasing for a mark made of circles and straight lines.

    python scripts/make_icon.py                # packaging/revlab.ico
    python scripts/make_icon.py --android      # android/res/mipmap-*/ic_launcher.png
    python scripts/make_icon.py --png out.png --size 512
"""

from __future__ import annotations

import struct
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

BACKDROP_TOP = (16, 24, 32)      # near-black slate
BACKDROP_BOTTOM = (12, 62, 74)   # deep teal
GLASS = (232, 244, 255)          # the magnifier: cold white
MARK = (53, 208, 186)            # the chevron inside it: teal

ICO_SIZES = (16, 24, 32, 48, 64, 128, 256)
ANDROID_SIZES = {"mdpi": 48, "hdpi": 72, "xhdpi": 96, "xxhdpi": 144, "xxxhdpi": 192}


# ---- geometry (all coordinates live in a 0..1 square) ----------------------
def _rounded_rect(u: float, v: float, radius: float = 0.20) -> bool:
    """Inside a rounded square that fills most of the canvas."""
    half, span = 0.5, 0.5 - 0.02
    dx = abs(u - half) - (span - radius)
    dy = abs(v - half) - (span - radius)
    if dx <= 0 and dy <= 0:
        return True
    return (max(dx, 0.0) ** 2 + max(dy, 0.0) ** 2) <= radius * radius


def _ring(u: float, v: float, cx: float, cy: float, radius: float, width: float) -> bool:
    return abs(((u - cx) ** 2 + (v - cy) ** 2) ** 0.5 - radius) <= width / 2


def _segment(u: float, v: float, ax: float, ay: float, bx: float, by: float,
             width: float) -> bool:
    px, py = u - ax, v - ay
    qx, qy = bx - ax, by - ay
    length = qx * qx + qy * qy
    t = 0.0 if length == 0 else max(0.0, min(1.0, (px * qx + py * qy) / length))
    dx, dy = px - t * qx, py - t * qy
    return (dx * dx + dy * dy) ** 0.5 <= width / 2


def _pixel(u: float, v: float) -> tuple[int, int, int, int]:
    """One sample of the mark: a lens over a code chevron on a teal plate."""
    if not _rounded_rect(u, v):
        return (0, 0, 0, 0)
    mix = min(1.0, max(0.0, v))
    plate = tuple(
        int(BACKDROP_TOP[i] + (BACKDROP_BOTTOM[i] - BACKDROP_TOP[i]) * mix) for i in range(3)
    )
    if _segment(u, v, 0.60, 0.58, 0.82, 0.80, 0.088):        # magnifier handle
        return (*GLASS, 255)
    if _ring(u, v, 0.42, 0.40, 0.245, 0.075):                # magnifier rim
        return (*GLASS, 255)
    if (_segment(u, v, 0.35, 0.31, 0.44, 0.40, 0.055)
            or _segment(u, v, 0.44, 0.40, 0.35, 0.49, 0.055)):  # ">" in the lens
        return (*MARK, 255)
    return (*plate, 255)


# ---- rasterising -----------------------------------------------------------
def render(size: int) -> bytes:
    """RGBA bytes for one square icon: supersampled, then box-filtered down."""
    scale = 4 if size <= 64 else 2
    big = size * scale
    samples = bytearray(big * big * 4)
    step = 1.0 / big
    for row in range(big):
        v = (row + 0.5) * step
        base = row * big * 4
        for column in range(big):
            u = (column + 0.5) * step
            samples[base + column * 4 : base + column * 4 + 4] = bytes(_pixel(u, v))
    out = bytearray(size * size * 4)
    area = scale * scale
    for y in range(size):
        for x in range(size):
            totals = [0, 0, 0, 0]
            for dy in range(scale):
                offset = ((y * scale + dy) * big + x * scale) * 4
                for dx in range(scale):
                    index = offset + dx * 4
                    for channel in range(4):
                        totals[channel] += samples[index + channel]
            out[(y * size + x) * 4 : (y * size + x) * 4 + 4] = bytes(
                value // area for value in totals
            )
    return bytes(out)


# ---- encoders --------------------------------------------------------------
def _chunk(tag: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload)) + tag + payload
        + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
    )


def png_bytes(rgba: bytes, width: int, height: int) -> bytes:
    raw = b"".join(
        b"\x00" + rgba[row * width * 4 : (row + 1) * width * 4] for row in range(height)
    )
    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", header)
        + _chunk(b"IDAT", zlib.compress(raw, 9))
        + _chunk(b"IEND", b"")
    )


def _dib(rgba: bytes, size: int) -> bytes:
    """A 32-bit bottom-up DIB, which is what an ICO entry carries."""
    header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    body = bytearray()
    for row in range(size - 1, -1, -1):
        for column in range(size):
            index = (row * size + column) * 4
            red, green, blue, alpha = rgba[index : index + 4]
            body += bytes((blue, green, red, alpha))
    mask_row = ((size + 31) // 32) * 4
    return header + bytes(body) + bytes(mask_row * size)


def ico_bytes(images: list[tuple[int, bytes]]) -> bytes:
    entries, blobs = bytearray(), bytearray()
    offset = 6 + 16 * len(images)
    for size, rgba in images:
        dib = _dib(rgba, size)
        entries += struct.pack(
            "<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(dib), offset
        )
        offset += len(dib)
        blobs += dib
    return bytes(struct.pack("<HHH", 0, 1, len(images)) + entries + blobs)


# ---- entry point -----------------------------------------------------------
def build_ico(path: Path, sizes=ICO_SIZES) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(ico_bytes([(size, render(size)) for size in sizes]))
    return path


def build_android(directory: Path) -> list[Path]:
    written = []
    for density, size in ANDROID_SIZES.items():
        target = directory / f"mipmap-{density}" / "ic_launcher.png"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(png_bytes(render(size), size, size))
        written.append(target)
    return written


def main(argv: list[str]) -> int:
    args = list(argv[1:])
    if "--android" in args:
        for path in build_android(ROOT / "android" / "res"):
            print(f"wrote {path.relative_to(ROOT)}")
        return 0
    if "--png" in args:
        target = Path(args[args.index("--png") + 1])
        size = int(args[args.index("--size") + 1]) if "--size" in args else 512
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(png_bytes(render(size), size, size))
        print(f"wrote {target} ({size}x{size})")
        return 0
    path = build_ico(ROOT / "packaging" / "revlab.ico")
    print(f"wrote {path.relative_to(ROOT)} "
          f"({', '.join(str(size) for size in ICO_SIZES)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
