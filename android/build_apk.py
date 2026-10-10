"""Build the RevLab Android client without Gradle.

Gradle would add a build system, a plugin repository and a daemon to compile two
small classes and run the four tools that do all the work anyway: ``aapt2``
(resources), ``javac`` (this is Java, not Kotlin), ``d8`` (Dalvik bytecode) and
``zipalign`` + ``apksigner`` (a package Android will install). Those ship in the
Android SDK's build-tools, so the SDK is the only real requirement.

    python android/build_apk.py
    python android/build_apk.py --sdk C:\\Android\\Sdk --java-home C:\\jdk-17

Why Python rather than a PowerShell script: on a machine whose user profile is
under a non-ASCII path, PowerShell 5.1 does not pass non-ASCII or
``-Dname=value`` arguments to native programs intact (``aapt2`` was handed a
mangled ``android.jar`` path). ``subprocess`` with an argument list hands Windows
the exact UTF-16 command line, which is the whole difference.

The ``d8`` and ``apksigner`` batch files are bypassed for the same reason: their
jars are started directly, so nothing depends on ``JAVA_HOME`` reaching a child
``cmd.exe`` intact.

One constraint comes from the toolchain rather than from this script: R8 (d8) in
every tested build-tools aborts with a NullPointerException on class files that
carry an InnerClasses attribute, so the Android sources keep to one top-level
class per file. ``python android/check_toolchain.py`` reproduces that finding.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

# The tools print UTF-8 and this console may be a legacy code page: without this,
# printing a Chinese path aborts the build with UnicodeEncodeError.
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
BUILD = HERE / "build"
DIST = ROOT / "dist"
KEYSTORE = HERE / "revlab-debug.keystore"
STORE_PASS = "revlab-mobile"          # development keystore: not a secret
KEY_ALIAS = "revlab"
APP_VERSION_NAME = "0.2.0"
APP_VERSION_CODE = 1
MIN_SDK = 24

#: sdkmanager package -> the dl.google.com zip that contains the same thing,
#: used when sdkmanager cannot run (no cmdline-tools, no licences accepted).
PACKAGE_ZIPS = {
    "build-tools;34.0.0": (
        "https://dl.google.com/android/repository/build-tools_r34-windows.zip",
        "build-tools/34.0.0",
    ),
    "platforms;android-34": (
        "https://dl.google.com/android/repository/platform-34_r03.zip",
        "platforms/android-34",
    ),
    "platform-tools": (
        "https://dl.google.com/android/repository/platform-tools-latest-windows.zip",
        "platform-tools",
    ),
}

JAVA_CANDIDATES = (
    r"D:\nd",
    r"D:\jdk",
    r"D:\Java",
    r"C:\Program Files\Java\jdk-17",
    r"C:\Program Files\Java\jdk-16",
    r"C:\Program Files\Eclipse Adoptium\jdk-21",
    r"C:\Program Files\Eclipse Adoptium\jdk-17",
    r"C:\Program Files\Android\Android Studio\jbr",
)

#: R8 (d8) from build-tools aborts with a NullPointerException on any class file
#: that carries an InnerClasses attribute -- nested or anonymous classes. It
#: affects every build-tools tested (29.0.3 through 36.0.0) and every JDK used to
#: run it, so the client keeps to one top-level class per file instead. When a
#: future edit reintroduces nesting, this text is what the operator reads.
NESTING_HINT = (
    "d8 refused a class file that carries an InnerClasses attribute -- that is a\n"
    "   known failure of R8 in build-tools here, not a bug in the source.\n"
    "   fix: keep android/java/**/{0} to top-level classes, i.e. no nested or\n"
    "   anonymous classes. Run `python android/check_toolchain.py` to see the\n"
    "   toolchain decide for itself."
)


class BuildError(RuntimeError):
    """Something the operator has to fix (a tool is missing, a step failed)."""


def step(message: str) -> None:
    print(f"== {message}", flush=True)


def run(args: list[str], cwd: Path | None = None, env: dict | None = None,
        check: bool = True, stdin_data: bytes | None = None) -> subprocess.CompletedProcess:
    """Run one tool and stream nothing: the caller reports, the tool writes."""
    printable = " ".join(args)
    if os.environ.get("REVLAB_VERBOSE"):
        print(f"   $ {printable}", flush=True)
    result = subprocess.run(
        args, cwd=str(cwd) if cwd else None, env=env, input=stdin_data,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    output = result.stdout.decode("utf-8", "replace").strip()
    if check and result.returncode != 0:
        raise BuildError(f"{args[0]} failed (exit {result.returncode}):\n{output}")
    return subprocess.CompletedProcess(args, result.returncode, output, "")


# ---- toolchain discovery ---------------------------------------------------
def resolve_java_home(explicit: str | None) -> Path:
    """A JDK with javac: 11 or newer, newest-looking candidate first."""
    candidates: list[str] = []
    if explicit:
        candidates.append(explicit)
    for name in ("REVLAB_JAVA_HOME", "GHIDRA_MCP_JAVA_HOME", "JAVA_HOME"):
        value = os.environ.get(name)
        if value:
            candidates.append(value)
    candidates.extend(JAVA_CANDIDATES)
    adoptium = Path(r"C:\Program Files\Eclipse Adoptium")
    if adoptium.is_dir():
        candidates.extend(
            str(item) for item in sorted(adoptium.iterdir(), reverse=True)
        )
    for candidate in candidates:
        if candidate and (Path(candidate) / "bin" / "javac.exe").is_file():
            return Path(candidate)
    raise BuildError(
        "no JDK found (javac 11+ is required); pass --java-home C:\\path\\to\\jdk"
    )


def resolve_sdk(explicit: str | None) -> Path:
    """The Android SDK root: where cmdline-tools lives."""
    candidates = [
        explicit,
        os.environ.get("REVLAB_ANDROID_SDK"),
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
        str(Path(os.environ.get("LOCALAPPDATA", "")) / "Android" / "Sdk"),
    ]
    for candidate in candidates:
        if candidate and (Path(candidate) / "cmdline-tools").is_dir():
            return Path(candidate)
    raise BuildError(
        "no Android SDK found; install the command-line tools or pass --sdk "
        "(expected something like %LOCALAPPDATA%\\Android\\Sdk)"
    )


def sdkmanager_path(sdk: Path) -> Path | None:
    for pattern in ("cmdline-tools/latest/bin/sdkmanager.bat",
                    "cmdline-tools/*/bin/sdkmanager.bat"):
        found = sorted(sdk.glob(pattern))
        if found:
            return found[0]
    return None


def env_with_java(java_home: Path) -> dict:
    """JAVA_HOME and PATH for the tools' own convenience, nothing else."""
    env = dict(os.environ)
    env["JAVA_HOME"] = str(java_home)
    env["PATH"] = str(java_home / "bin") + os.pathsep + env.get("PATH", "")
    return env


def ensure_package(sdk: Path, package: str, target: Path, java_home: Path,
                   allow_install: bool) -> None:
    """Install one SDK package, through sdkmanager or straight from Google."""
    if target.exists():
        return
    if not allow_install:
        raise BuildError(f"{target} is missing and --skip-install was given")

    manager = sdkmanager_path(sdk)
    if manager:
        step(f"sdkmanager: {package}")
        env = env_with_java(java_home)
        # The licences have to be accepted before anything can be installed;
        # sdkmanager asks on stdin, so answer "yes" enough times for every
        # licence text it decides to show.
        run([str(manager), "--licenses"], cwd=manager.parent, env=env,
            check=False, stdin_data=b"y\n" * 80)
        # No --sdk_root: sdkmanager derives it from its own location, which keeps
        # every argument ASCII even when the SDK lives under a non-ASCII path.
        run([str(manager), package], cwd=manager.parent, env=env, check=False)
        if target.exists():
            print(f"   installed into {target}")
            return
        print(f"   sdkmanager did not produce {target}; trying the direct download")

    url, relative = PACKAGE_ZIPS.get(package, ("", ""))
    if not url:
        raise BuildError(f"cannot install {package}: no known download URL")
    step(f"downloading {package}")
    archive = Path(os.environ.get("TEMP", ".")) / f"revlab-{package.replace(';', '-')}.zip"
    urllib.request.urlretrieve(url, archive)
    staging = Path(os.environ.get("TEMP", ".")) / f"revlab-stage-{os.getpid()}"
    with zipfile.ZipFile(archive) as bundle:
        bundle.extractall(staging)
    # The zips wrap everything in one directory whose name is not always the
    # name the SDK expects (`android-14` for build-tools 34), so move whatever
    # came out to where the SDK tools look for it.
    inner = [item for item in staging.iterdir() if item.is_dir()]
    if not inner:
        raise BuildError(f"{archive} did not contain a directory")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(inner[0]), str(target))
    shutil.rmtree(staging, ignore_errors=True)
    archive.unlink(missing_ok=True)
    if not target.exists():
        raise BuildError(f"{package} did not end up in {target}")
    print(f"   installed into {target}")


def add_to_zip(archive: Path, files: list[Path]) -> None:
    """Append files to an existing zip without rewriting what is already there."""
    with zipfile.ZipFile(archive, "a", zipfile.ZIP_DEFLATED) as bundle:
        for path in files:
            bundle.write(path, path.name)


def build(options: argparse.Namespace) -> Path:
    java_home = resolve_java_home(options.java_home)
    step(f"JDK: {java_home}")
    env = env_with_java(java_home)
    java = java_home / "bin" / "java.exe"
    keytool = java_home / "bin" / "keytool.exe"

    sdk = resolve_sdk(options.sdk)
    step(f"SDK: {sdk}")
    build_tools = sdk / "build-tools" / options.build_tools
    platform = sdk / "platforms" / f"android-{options.api}"
    android_jar = platform / "android.jar"
    ensure_package(sdk, f"build-tools;{options.build_tools}", build_tools, java_home,
                   not options.skip_install)
    ensure_package(sdk, f"platforms;android-{options.api}", platform, java_home,
                   not options.skip_install)

    aapt2 = build_tools / "aapt2.exe"
    zipalign = build_tools / "zipalign.exe"
    d8_jar = build_tools / "lib" / "d8.jar"
    apksigner_jar = build_tools / "lib" / "apksigner.jar"
    for tool in (aapt2, zipalign, d8_jar, apksigner_jar):
        if not tool.is_file():
            raise BuildError(
                f"{tool} is missing -- install build-tools;{options.build_tools}"
            )
    if not android_jar.is_file():
        raise BuildError(f"{android_jar} is missing -- install platforms;android-{options.api}")

    if options.dry_run:
        step("dry run: toolchain resolved, nothing built")
        return Path()

    if BUILD.exists():
        shutil.rmtree(BUILD)
    for child in ("res", "classes", "dex"):
        (BUILD / child).mkdir(parents=True, exist_ok=True)
    DIST.mkdir(parents=True, exist_ok=True)

    # 1. resources + manifest -> a package with no code in it yet
    step("aapt2 compile + link")
    run([str(aapt2), "compile", "--dir", str(HERE / "res"), "-o", str(BUILD / "res.zip")])
    run([
        str(aapt2), "link",
        "-o", str(BUILD / "base.apk"),
        "-I", str(android_jar),
        "--manifest", str(HERE / "AndroidManifest.xml"),
        str(BUILD / "res.zip"),
        "--min-sdk-version", str(MIN_SDK),
        "--target-sdk-version", str(options.api),
        "--version-code", str(options.version_code),
        "--version-name", options.version_name,
    ])

    # 2. Java -> classes
    step("javac --release 11")
    sources = [str(path) for path in (HERE / "java").rglob("*.java")]
    run([str(java_home / "bin" / "javac.exe"), "-encoding", "UTF-8", "--release", "11",
         "-classpath", str(android_jar), "-d", str(BUILD / "classes")] + sources)

    # 3. classes -> Dalvik bytecode (the jar is started directly: no .bat, no
    #    dependency on JAVA_HOME reaching a child cmd.exe intact; the class files
    #    are passed one by one, which is the input shape that works here)
    step("d8")
    classes = sorted(str(path) for path in (BUILD / "classes").rglob("*.class"))
    nested = [Path(item).name for item in classes if "$" in Path(item).name]
    if nested:
        print(f"   note: {len(nested)} nested class file(s) present ({', '.join(nested[:3])}"
              f"{' ...' if len(nested) > 3 else ''}); R8 here rejects those")
    try:
        run([str(java), "-cp", str(d8_jar), "com.android.tools.r8.D8",
             "--lib", str(android_jar), "--min-api", str(MIN_SDK),
             "--output", str(BUILD / "dex")] + classes, env=env)
    except BuildError as exc:
        if nested:
            raise BuildError(f"{exc}\n   {NESTING_HINT.format('*.java')}") from exc
        raise

    # 4. the code goes into the package
    step("packaging classes.dex")
    unsigned = BUILD / "unsigned.apk"
    shutil.copyfile(BUILD / "base.apk", unsigned)
    dex_files = sorted((BUILD / "dex").glob("*.dex"))
    if not dex_files:
        raise BuildError("d8 produced no .dex file")
    add_to_zip(unsigned, dex_files)

    # 5. align, then sign (v1 + v2: installable from Android 7 to 15)
    step("zipalign + apksigner")
    aligned = BUILD / "aligned.apk"
    run([str(zipalign), "-f", "-p", "4", str(unsigned), str(aligned)])

    if not KEYSTORE.is_file():
        step(f"generating a development keystore ({KEYSTORE.name})")
        run([str(keytool), "-genkeypair", "-keystore", str(KEYSTORE),
             "-storetype", "PKCS12", "-alias", KEY_ALIAS,
             "-storepass", STORE_PASS, "-keypass", STORE_PASS,
             "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
             "-dname", "CN=RevLab Mobile, OU=client, O=RevLab, C=CN"])

    final = DIST / f"RevLab-Mobile-{options.version_name}.apk"
    run([str(java), "-cp", str(apksigner_jar), "com.android.apksigner.ApkSignerTool",
         "sign", "--ks", str(KEYSTORE), "--ks-pass", f"pass:{STORE_PASS}",
         "--key-pass", f"pass:{STORE_PASS}", "--ks-key-alias", KEY_ALIAS,
         "--v1-signing-enabled", "true", "--v2-signing-enabled", "true",
         # v3/v4 are for rotation and incremental installs; v4 would leave a
         # second file next to the APK for no benefit here.
         "--v3-signing-enabled", "false", "--v4-signing-enabled", "false",
         "--out", str(final), str(aligned)], env=env)

    step("verifying the artifact")
    verify = run([str(java), "-cp", str(apksigner_jar),
                  "com.android.apksigner.ApkSignerTool", "verify", "--print-certs",
                  str(final)], env=env, check=False)
    if verify.returncode != 0:
        raise BuildError(f"apksigner verify failed:\n{verify.stdout}")
    signer = next((line.strip() for line in verify.stdout.splitlines()
                   if "certificate DN" in line), "verified")

    facts = descriptor(final, aapt2)
    problems = []
    if not facts["has_dex"]:
        problems.append("no classes.dex in the package")
    if not facts["arsc_stored"]:
        problems.append("resources.arsc is compressed (Android 11+ refuses to install)")
    if not facts["launchable"]:
        problems.append("no launchable activity (the launcher would not show it)")
    if facts["package"] != "com.revlab.mobile":
        problems.append(f"unexpected package name {facts['package']}")

    print()
    print(f"   package      : {facts['package']} {facts['version_name']} "
          f"(minSdk {facts['min_sdk']}, targetSdk {facts['target_sdk']})")
    print(f"   entries      : {facts['entries']}, classes.dex: "
          f"{'yes' if facts['has_dex'] else 'NO'}, resources.arsc stored: "
          f"{'yes' if facts['arsc_stored'] else 'NO'}")
    print(f"   signature    : {signer}")
    if problems:
        raise BuildError("the APK is not installable:\n  - " + "\n  - ".join(problems))

    size = final.stat().st_size / 1024
    print()
    print(f"APK ready: {final} ({size:.1f} KiB)")
    print(f"install  : adb install -r \"{final}\"")
    print("use      : start RevLab on the PC, press 共享给浏览器/手机, paste the")
    print("           http://<pc-ip>:<port>/?t=<code> address into the app")
    return final


def descriptor(apk: Path, aapt2: Path) -> dict:
    """What Android will believe about the package, read back from the APK.

    Checking the artifact rather than trusting the build is the same instinct as
    the rest of this project: ``resources.arsc`` uncompressed and a launchable
    activity are exactly what stands between "it built" and "it installs".
    """
    import re

    with zipfile.ZipFile(apk) as bundle:
        names = bundle.namelist()
        arsc = next((item for item in bundle.infolist()
                     if item.filename == "resources.arsc"), None)
    text = run([str(aapt2), "dump", "badging", str(apk)], check=False).stdout
    package = re.search(r"package: name='([^']+)' versionCode='(\d+)' "
                        r"versionName='([^']*)'", text)
    sdk = re.search(r"sdkVersion:'(\d+)'", text)
    target = re.search(r"targetSdkVersion:'(\d+)'", text)
    return {
        "entries": len(names),
        "has_dex": "classes.dex" in names,
        "arsc_stored": bool(arsc) and arsc.compress_type == zipfile.ZIP_STORED,
        "package": package.group(1) if package else "?",
        "version_name": package.group(3) if package else "?",
        "min_sdk": sdk.group(1) if sdk else "?",
        "target_sdk": target.group(1) if target else "?",
        "launchable": "launchable-activity" in text,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="build_apk.py",
        description="Build the RevLab Android client with the SDK tools (no Gradle)",
    )
    parser.add_argument("--sdk", help="Android SDK root (the one holding cmdline-tools)")
    parser.add_argument("--java-home", help="JDK used by javac/d8/keytool/apksigner")
    parser.add_argument("--api", type=int, default=34, help="platform to build against")
    parser.add_argument("--build-tools", default="34.0.0")
    parser.add_argument("--version-name", default=APP_VERSION_NAME)
    parser.add_argument("--version-code", type=int, default=APP_VERSION_CODE)
    parser.add_argument("--skip-install", action="store_true",
                        help="never touch the SDK; fail if a component is missing")
    parser.add_argument("--dry-run", action="store_true",
                        help="resolve the toolchain and stop")
    options = parser.parse_args(argv)

    try:
        build(options)
    except BuildError as exc:
        print(f"!! {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
