"""Console-script shim that execs the bundled ``trishul`` binary.

This is the entry point registered as the ``trishul`` console script. It
locates the native binary bundled inside this package (``trishul_cli/bin/``)
and hands control to it, forwarding argv and the exit code. No network
access and no download — the correct binary for the platform ships inside
the platform-specific wheel.
"""

import os
import sys


def _binary_path():
    """Absolute path to the bundled ``trishul`` binary for this platform."""
    here = os.path.dirname(os.path.abspath(__file__))
    name = "trishul.exe" if os.name == "nt" else "trishul"
    return os.path.join(here, "bin", name)


def main():
    """Exec the bundled binary, forwarding argv and exit status."""
    binary = _binary_path()

    if not os.path.isfile(binary):
        sys.stderr.write(
            "trishul: bundled binary not found at {0}\n".format(binary)
        )
        sys.stderr.write(
            "This wheel may be installed on an unsupported platform.\n"
        )
        return 1

    argv = [binary] + sys.argv[1:]

    if os.name == "nt":
        # os.execv on Windows has argv-quoting quirks and does not replace
        # the process cleanly, so run as a subprocess and forward the code.
        import subprocess

        try:
            return subprocess.run(argv).returncode
        except KeyboardInterrupt:
            return 130

    # POSIX: make sure the bundled binary is executable, then replace this
    # process image with it. os.execv does not return on success.
    try:
        mode = os.stat(binary).st_mode
        os.chmod(binary, mode | 0o111)
    except OSError:
        pass

    try:
        os.execv(binary, argv)
    except OSError as exc:  # pragma: no cover - exec rarely fails
        sys.stderr.write("trishul: failed to exec binary: {0}\n".format(exc))
        return 126

    return 127  # unreachable; execv replaces the process on success


if __name__ == "__main__":
    sys.exit(main())
