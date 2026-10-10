"""PyInstaller entry point for the command line (``RevLabCLI.exe``)."""

from revlab.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
