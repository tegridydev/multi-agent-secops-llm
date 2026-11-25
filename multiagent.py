"""Keep the original entry point. New commands also work via secops-harness."""

import sys

from secops_harness.cli import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:] or ["demo"]))
