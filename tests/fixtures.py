"""Compatibility shim: the sample builders moved into :mod:`revlab.demo`.

The builders are product code -- the desktop app's "generate a demo target"
button calls the very same functions -- so they live in ``revlab/demo.py`` now.
This module re-exports them, including the private helpers the tests reach into,
so existing imports keep working unchanged.
"""

from __future__ import annotations

from revlab.demo import (  # noqa: F401  - re-exported on purpose
    _MANIFEST_STRINGS,
    _NDK_BANNER,
    _attr,
    _section,
    _start_element,
    _string_pool,
    build_axml,
    build_demo_apk,
    build_elf,
    build_manifest_apk,
    build_manifest_axml,
    encrypted_dex_blob,
    plain_dex_blob,
    random_blob,
)
