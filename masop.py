# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Run MASOP from an extracted release or checkout with uv run masop.py."""

import sys


def launch() -> int:
    if sys.version_info < (3, 11):  # noqa: UP036 - handles direct launches with an older interpreter
        print("MASOP needs Python 3.11 or later. Try: uv run masop.py", file=sys.stderr)
        return 2
    from secops_harness.menu import main

    return main()


if __name__ == "__main__":
    raise SystemExit(launch())
