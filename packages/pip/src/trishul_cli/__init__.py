"""trishul-cli — platform binary wheel for the trishul security scanner.

Each published wheel bundles the native ``trishul`` Go binary for one
platform under :mod:`trishul_cli.bin`. The console-script ``trishul`` is a
tiny pure-Python shim (:func:`trishul_cli._exec.main`) that ``os.execv``s
the bundled binary. The binary itself is injected at wheel-build time by
``scripts/pip/build-wheels.py`` and is therefore absent from the source
tree.
"""

__version__ = "0.0.1"
