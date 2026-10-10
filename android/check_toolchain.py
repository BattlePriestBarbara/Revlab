"""Ask the Android toolchain what it can and cannot do, and report it plainly.

Two failures cost hours on the machine this was written on, and neither said what
was wrong:

* PowerShell 5.1 handed ``aapt2`` a mangled ``android.jar`` path when the SDK
  lives under a non-ASCII user name (``C:\\Users\\<Chinese>\\AppData\\Local\\...``);
* R8 (``d8``) aborted with ``NullPointerException: Cannot invoke "String.length()"
  because "<parameter1>" is null`` on any class file carrying an InnerClasses
  attribute -- nested or anonymous classes -- in every build-tools from 29.0.3 to
  36.0.0, under JDK 16 and JDK 25 alike.

So this script compiles a few known-shape classes and reports, per shape, whether
the dex step is possible. It is a diagnostic, not a build:

    python android/check_toolchain.py
    python android/check_toolchain.py --sdk C:\\Android\\Sdk --java-home C:\\jdk-17
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_apk import (  # noqa: E402 - after the path fix above
    BUILD,
    BuildError,
    env_with_java,
    resolve_java_home,
    resolve_sdk,
)

#: class name -> (source, explanation). Each shape is a hypothesis about what the
#: dex step accepts; the point of the script is that the answer is measured.
#: The file name has to match the public class, so it is derived from the key.
SHAPES = {
    "Plain": (
        "public class Plain { public int add(int a, int b) { return a + b; } }\n",
        "no library types, no nesting",
    ),
    "PlainActivity": (
        "import android.app.Activity;\n"
        "import android.os.Bundle;\n"
        "import android.widget.TextView;\n"
        "public class PlainActivity extends Activity {\n"
        "  @Override protected void onCreate(Bundle state) {\n"
        "    super.onCreate(state);\n"
        "    setContentView(new TextView(this));\n"
        "  }\n"
        "}\n",
        "extends an android.jar class (library resolution required)",
    ),
    "Nested": (
        "import android.view.View;\n"
        "import android.widget.Button;\n"
        "public class Nested {\n"
        "  public void wire(Button b) {\n"
        "    b.setOnClickListener(new View.OnClickListener() {\n"
        "      public void onClick(View v) { }\n"
        "    });\n"
        "  }\n"
        "}\n",
        "contains an anonymous class (InnerClasses attribute)",
    ),
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check what the dex step accepts")
    parser.add_argument("--sdk")
    parser.add_argument("--java-home")
    parser.add_argument("--build-tools", default="34.0.0")
    parser.add_argument("--api", type=int, default=34)
    options = parser.parse_args(argv)

    java_home = resolve_java_home(options.java_home)
    sdk = resolve_sdk(options.sdk)
    java = java_home / "bin" / "java.exe"
    javac = java_home / "bin" / "javac.exe"
    env = env_with_java(java_home)
    android_jar = sdk / "platforms" / f"android-{options.api}" / "android.jar"
    d8_jar = sdk / "build-tools" / options.build_tools / "lib" / "d8.jar"
    print(f"JDK    : {java_home}")
    print(f"SDK    : {sdk}")
    print(f"d8     : {d8_jar} -> {'present' if d8_jar.is_file() else 'MISSING'}")
    print(f"android: {android_jar} -> {'present' if android_jar.is_file() else 'MISSING'}")
    if not (d8_jar.is_file() and android_jar.is_file()):
        raise BuildError("build-tools or platform is missing; run build_apk.py once")

    work = BUILD / "toolchain-check"
    if work.exists():
        shutil.rmtree(work)
    source_dir = work / "src"
    source_dir.mkdir(parents=True)
    for name, (body, _) in SHAPES.items():
        (source_dir / f"{name}.java").write_text(body, encoding="utf-8")

    print("\nclass shapes (the dex step either takes them or it does not):")
    verdicts: dict[str, bool] = {}
    for name, (_, explanation) in SHAPES.items():
        classes = work / f"classes-{name}"
        classes.mkdir(parents=True)
        compiled = subprocess.run(
            [str(javac), "-encoding", "UTF-8", "--release", "11", "-Xlint:-options",
             "-classpath", str(android_jar), "-d", str(classes),
             str(source_dir / f"{name}.java")], capture_output=True)
        if compiled.returncode != 0:
            print(f"  {name:9} javac failed: "
                  f"{compiled.stderr.decode('utf-8', 'replace').strip()[:90]}")
            verdicts[name] = False
            continue
        dex = work / f"dex-{name}"
        dex.mkdir(parents=True)
        files = sorted(str(item) for item in classes.rglob("*.class"))
        built = subprocess.run(
            [str(java), "-cp", str(d8_jar), "com.android.tools.r8.D8",
             "--lib", str(android_jar), "--min-api", "24", "--output", str(dex)]
            + files, capture_output=True, env=env)
        made = sorted(item.name for item in dex.glob("*.dex"))
        verdicts[name] = built.returncode == 0 and bool(made)
        fault = next((line.strip() for line in
                      (built.stdout + built.stderr).decode("utf-8", "replace").splitlines()
                      if "NullPointer" in line or "error" in line.lower()), "")
        print(f"  {name:9} {'OK  ' if verdicts[name] else 'FAIL'}  ({explanation})"
              f"{'  ' + fault[:80] if fault else ''}")

    print("\nwhat this means:")
    if verdicts.get("PlainActivity") and not verdicts.get("Nested"):
        print("  * class files with an InnerClasses attribute cannot be dexed here, so")
        print("    the Android sources stay one top-level class per file (no nested or")
        print("    anonymous classes). build_apk.py checks that and says so.")
    elif all(verdicts.values()):
        print("  * every shape works: nesting is fine on this machine.")
    else:
        print("  * the dex step is unusable here; install a JDK 17 and rerun with")
        print("    --java-home, or build the app in Android Studio instead.")
    print(f"\nwork dir: {work}")
    return 0 if verdicts.get("PlainActivity") else 1


if __name__ == "__main__":
    raise SystemExit(main())
