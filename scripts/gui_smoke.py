"""Headless smoke test: build the real window, click the real buttons.

Run:  python scripts/gui_smoke.py
Not part of the unit suite: it needs a display and takes a few seconds.
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import tkinter as tk  # noqa: E402

from revlab import desktop  # noqa: E402
from revlab.config import load_config  # noqa: E402


def pump(window, seconds: float) -> None:
    """Run the Tk event loop until the worker finishes or time runs out."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        window.root.update()
        if not window.busy:
            return
        time.sleep(0.05)


def main() -> int:
    sandbox = Path(tempfile.mkdtemp(prefix="revlab-gui-"))
    config_file = sandbox / "revlab.toml"
    config_file.write_text(
        f'[workspace]\nroot = "{(sandbox / "workspaces").as_posix()}"\n'
        '[scope]\nauthorised = ["demo.apk"]\n',
        encoding="utf-8",
    )
    config = load_config(config_file)
    root = tk.Tk()
    root.withdraw()  # no window on screen; the widgets are still real
    window = desktop.Window(root, config, config_file, sandbox / "gui.log", ["smoke"])
    pump(window, 1.0)
    print("built:", len(window.notebook.tabs()), "tabs,", window.status_var.get())

    window.make_sample()
    pump(window, 20.0)
    sample = window.target.get()
    print("sample:", sample)
    assert sample and Path(sample).exists(), "sample was not produced"

    window.analyze()
    pump(window, 120.0)
    rows = window.findings.get_children()
    print("findings in tree:", len(rows))
    print("first row:", window.findings.item(rows[0], "values") if rows else None)
    assert rows, "the findings table stayed empty"

    window.report()
    pump(window, 30.0)
    print("report:", [str(path) for path in window.written])
    assert window.written, "no report was written"

    window.doctor()
    pump(window, 60.0)
    print("doctor lines:", len(window.doctorbox.get("1.0", "end").splitlines()))

    # A refused run must leave the fix one click away (the gate stays default-deny).
    # demo.apk is already authorised in this config, so nothing is offered...
    window.target.set(str(Path(sample).resolve()))
    window.offer_scope_fix()
    assert window.scope_entry.get() == "", "must not offer a target that is already listed"
    # ...while an unauthorised target gets its name filled in for one click.
    window.target.set(str(Path(sample).resolve().with_name("another-demo.apk")))
    window.offer_scope_fix()
    print("prefilled scope entry:", window.scope_entry.get())
    assert window.scope_entry.get() == "another-demo.apk", "scope help did not prefill"
    window.scope_entry.set("")

    window.scope_add()
    window.scope_entry.set("com.example.extra")
    window.scope_add()
    window.scope_save()
    pump(window, 10.0)
    print("scope now:", load_config(config_file).authorised)
    print("log tail:", [line for line in window.logbox.get("1.0", "end").splitlines()][-4:])
    root.destroy()
    print("SMOKE OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
