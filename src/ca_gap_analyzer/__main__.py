"""Lets the tool run as `python -m ca_gap_analyzer`."""

import sys

from .cli import main

sys.exit(main())
