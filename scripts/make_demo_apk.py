"""Build a synthetic APK so the first run needs no real target.

The point of a bundled demo is *legality and reproducibility*: you cannot debug
your own triage logic against someone else's app, and a real sample cannot be
committed. This writes a small APK whose every interesting property is known in
advance, using the same builders the test suite uses (``tests/fixtures.py``), so
the sample cannot drift away from what the tests assert:

* ``AndroidManifest.xml`` -- real binary AXML (package, SDK levels, permissions);
* ``classes.dex``         -- DEX magic followed by noise: an *encrypted* payload,
                             which must be reported as critical, not as code;
* ``classes2.dex``        -- a structurally plausible plain DEX;
* ``lib/x86_64``, ``lib/arm64-v8a`` -- two valid ELF shared objects;
* ``assets/payload.bin``  -- 1 MiB of high-entropy filler (packed blob);
* ``resources.arsc``      -- minimal resource table.

Usage::

    python scripts/make_demo_apk.py [output.apk]     # default samples/demo.apk
    python -m revlab triage samples/demo.apk

The output is ignored by git (``*.apk``) -- never commit a target.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from revlab import demo  # noqa: E402  - needs the repo root on sys.path

DEFAULT_OUTPUT = ROOT / "samples" / "demo.apk"


def main(argv: list[str]) -> int:
    output = Path(argv[1]).resolve() if len(argv) > 1 else DEFAULT_OUTPUT
    path = demo.build_demo_apk(output)
    size_kib = path.stat().st_size / 1024

    print(f"wrote {path} ({size_kib:.0f} KiB)")
    print("expected triage findings:")
    print("  - critical : classes.dex is not real bytecode (encrypted/packed DEX)")
    print("  - medium+  : high-entropy asset, native libs worth a Ghidra pass")
    print("\nnext:")
    print(f"  python -m revlab triage \"{path}\"")
    print("  (add the sample to [scope] authorised only if you also want Frida runs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
