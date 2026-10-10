"""PyInstaller entry point for the desktop window (``RevLab.exe``).

A frozen build needs a *script*, not a module path, so the two entry points live
here and are shared by both spec files.
"""

from revlab.desktop import main

if __name__ == "__main__":
    raise SystemExit(main())
