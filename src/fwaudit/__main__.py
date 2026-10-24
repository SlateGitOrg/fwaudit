"""Allow ``python -m fwaudit``."""

import sys

from fwaudit.cli import main

sys.exit(main())
