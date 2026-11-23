#!/usr/bin/env python3
"""Build per-platform binary wheels for ``trishul-cli`` from goreleaser dist/.

Each wheel bundles the native ``trishul`` binary for one platform under
``trishul_cli/bin/`` together with the pure-Python console-script shim, and is
tagged with the matching wheel platform tag (ruff/maturin style).

Tool assumptions
----------------
* Python **3.11+** only (uses the stdlib ``tomllib`` to read ``pyproject.toml``).
* **No third-party tools.** Wheels are assembled directly as zip archives with
  the standard library, so neither ``wheel``/``build`` nor ``setuptools`` are
  required and no network access happens. The output is deterministic (fixed
  zip timestamps, sorted RECORD) so repeated builds are byte-identical.

Input layout
------------
The goreleaser ``dist/`` tree (``goreleaser release`` / ``build``) unpacks each
build into a directory whose name encodes the target, e.g.::

    dist/trishul-cli_darwin_arm64_v8.0/trishul
    dist/trishul-cli_linux_amd64_v1/trishul
    dist/trishul-cli_windows_amd64_v1/trishul.exe

We locate binaries by globbing and read the os/arch from the directory name, so
trailing GOAMD64/GOARM64 variant suffixes do not matter.

Usage
-----
    python scripts/pip/build-wheels.py \
        --dist dist \
        --out packages/pip/wheelhouse \
        [--version 1.2.3]

Any platform whose binary is missing from ``dist/`` is skipped with a warning
(so a local partial build still works); use ``--require-all`` to fail instead.
Exit status is non-zero if no wheels could be built at all.
"""

import argparse
import base64
import hashlib
import io
import os
import sys
import tomllib
import zipfile

# (goos, goarch) -> wheel platform tag.
PLATFORMS = {
    ("darwin", "arm64"): "macosx_11_0_arm64",
    ("darwin", "amd64"): "macosx_10_9_x86_64",
    ("linux", "amd64"): "manylinux2014_x86_64",
    ("linux", "arm64"): "manylinux2014_aarch64",
    ("windows", "amd64"): "win_amd64",
}

GOOS = ("darwin", "linux", "windows")
GOARCH = ("amd64", "arm64")

PY_TAG = "py3"
ABI_TAG = "none"

# Fixed zip timestamp for reproducible archives (zip epoch minimum).
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))


def log(msg):
    sys.stderr.write(msg + "\n")


def load_metadata(pyproject_path):
    with open(pyproject_path, "rb") as fh:
        data = tomllib.load(fh)
    return data["project"]


def normalize_name(name):
    """PEP 503 / wheel filename normalization (dashes -> underscores)."""
    return name.replace("-", "_")


def discover_binaries(dist_dir):
    """Map (goos, goarch) -> path of the trishul binary found in dist/."""
    found = {}
    for entry in sorted(os.listdir(dist_dir)):
        full = os.path.join(dist_dir, entry)
        if not os.path.isdir(full):
            continue
        parts = entry.split("_")
        goos = next((p for p in parts if p in GOOS), None)
        goarch = next((p for p in parts if p in GOARCH), None)
        if goos is None or goarch is None:
            continue
        binname = "trishul.exe" if goos == "windows" else "trishul"
        binpath = os.path.join(full, binname)
        if os.path.isfile(binpath):
            found[(goos, goarch)] = binpath
    return found


def render_metadata(project, readme_text):
    """Render a PEP 566 METADATA file body."""
    lines = []
    lines.append("Metadata-Version: 2.1")
    lines.append("Name: {0}".format(project["name"]))
    lines.append("Version: {0}".format(project["version"]))
    if project.get("description"):
        lines.append("Summary: {0}".format(project["description"]))
    license_field = project.get("license")
    if isinstance(license_field, dict) and license_field.get("text"):
        lines.append("License: {0}".format(license_field["text"]))
    for author in project.get("authors", []):
        name = author.get("name", "")
        email = author.get("email", "")
        if name and email:
            lines.append("Author: {0}".format(name))
            lines.append("Author-email: {0} <{1}>".format(name, email))
        elif name:
            lines.append("Author: {0}".format(name))
    if project.get("requires-python"):
        lines.append("Requires-Python: {0}".format(project["requires-python"]))
    if project.get("keywords"):
        lines.append("Keywords: {0}".format(",".join(project["keywords"])))
    for key, url in project.get("urls", {}).items():
        lines.append("Project-URL: {0}, {1}".format(key, url))
    for classifier in project.get("classifiers", []):
        lines.append("Classifier: {0}".format(classifier))
    lines.append("Description-Content-Type: text/markdown")
    lines.append("")
    lines.append(readme_text.rstrip("\n"))
    lines.append("")
    return "\n".join(lines)


def render_wheel_file(tag):
    return (
        "Wheel-Version: 1.0\n"
        "Generator: trishul-build-wheels (1.0)\n"
        "Root-Is-Purelib: false\n"
        "Tag: {0}\n".format(tag)
    )


def render_entry_points():
    return "[console_scripts]\ntrishul = trishul_cli._exec:main\n"


def _record_hash(data):
    digest = hashlib.sha256(data).digest()
    b64 = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return "sha256={0}".format(b64), len(data)


def build_wheel(project, src_dir, readme_text, binary_path, goos, tag, out_dir):
    """Assemble one deterministic wheel; return the output path."""
    dist_name = normalize_name(project["name"])
    version = project["version"]
    distinfo = "{0}-{1}.dist-info".format(dist_name, version)
    binname = "trishul.exe" if goos == "windows" else "trishul"

    # (arcname, bytes, is_executable) in RECORD order.
    members = []

    # Pure-python package files from the source tree.
    for modname in ("__init__.py", "_exec.py"):
        with open(os.path.join(src_dir, "trishul_cli", modname), "rb") as fh:
            members.append(("trishul_cli/{0}".format(modname), fh.read(), False))

    # The bundled native binary.
    with open(binary_path, "rb") as fh:
        members.append(
            ("trishul_cli/bin/{0}".format(binname), fh.read(), True)
        )

    # dist-info metadata.
    members.append(
        ("{0}/METADATA".format(distinfo),
         render_metadata(project, readme_text).encode("utf-8"), False)
    )
    members.append(
        ("{0}/WHEEL".format(distinfo),
         render_wheel_file("{0}-{1}-{2}".format(PY_TAG, ABI_TAG, tag)).encode("utf-8"),
         False)
    )
    members.append(
        ("{0}/entry_points.txt".format(distinfo),
         render_entry_points().encode("utf-8"), False)
    )
    members.append(
        ("{0}/top_level.txt".format(distinfo), b"trishul_cli\n", False)
    )

    # RECORD (lists every file; its own line carries no hash/size).
    record_lines = []
    for arcname, data, _ in members:
        h, size = _record_hash(data)
        record_lines.append("{0},{1},{2}".format(arcname, h, size))
    record_path = "{0}/RECORD".format(distinfo)
    record_lines.append("{0},,".format(record_path))
    record_data = ("\n".join(record_lines) + "\n").encode("utf-8")

    wheel_name = "{0}-{1}-{2}-{3}-{4}.whl".format(
        dist_name, version, PY_TAG, ABI_TAG, tag
    )
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, wheel_name)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for arcname, data, is_exec in members:
            _write_member(zf, arcname, data, is_exec)
        _write_member(zf, record_path, record_data, False)

    with open(out_path, "wb") as fh:
        fh.write(buf.getvalue())
    return out_path


def _write_member(zf, arcname, data, is_exec):
    info = zipfile.ZipInfo(arcname, date_time=ZIP_EPOCH)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3  # unix, so the mode bits below are honored
    mode = 0o755 if is_exec else 0o644
    info.external_attr = (mode | 0o100000) << 16  # S_IFREG | mode
    zf.writestr(info, data)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dist", default=os.path.join(REPO_ROOT, "dist"),
        help="goreleaser dist/ directory (default: <repo>/dist)",
    )
    parser.add_argument(
        "--out", default=os.path.join(REPO_ROOT, "packages", "pip", "wheelhouse"),
        help="output directory for wheels (default: packages/pip/wheelhouse)",
    )
    parser.add_argument(
        "--pyproject",
        default=os.path.join(REPO_ROOT, "packages", "pip", "pyproject.toml"),
    )
    parser.add_argument(
        "--src", default=os.path.join(REPO_ROOT, "packages", "pip", "src"),
        help="package source tree containing trishul_cli/",
    )
    parser.add_argument(
        "--readme",
        default=os.path.join(REPO_ROOT, "packages", "pip", "README.md"),
    )
    parser.add_argument(
        "--version", default=None,
        help="override the version (e.g. from the release tag)",
    )
    parser.add_argument(
        "--require-all", action="store_true",
        help="fail if any supported platform binary is missing from dist/",
    )
    args = parser.parse_args(argv)

    project = load_metadata(args.pyproject)
    if args.version:
        project["version"] = args.version.lstrip("v")

    with open(args.readme, "r", encoding="utf-8") as fh:
        readme_text = fh.read()

    if not os.path.isdir(args.dist):
        log("error: dist directory not found: {0}".format(args.dist))
        return 2

    binaries = discover_binaries(args.dist)

    built = []
    missing = []
    for (goos, goarch), tag in PLATFORMS.items():
        binpath = binaries.get((goos, goarch))
        if binpath is None:
            missing.append((goos, goarch, tag))
            log("warning: no binary for {0}/{1} (tag {2}); skipping".format(
                goos, goarch, tag))
            continue
        out_path = build_wheel(
            project, args.src, readme_text, binpath, goos, tag, args.out
        )
        built.append(out_path)
        log("built {0}".format(os.path.relpath(out_path, REPO_ROOT)))

    if missing and args.require_all:
        log("error: --require-all set and {0} platform(s) missing".format(
            len(missing)))
        return 1

    if not built:
        log("error: no wheels built (no matching binaries found in dist/)")
        return 1

    log("done: {0} wheel(s) in {1}".format(len(built), args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
