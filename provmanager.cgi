#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""ProvManager CGI entry point."""

import sys

from provmanager import run_cgi


if __name__ == "__main__":
    sys.stdout.buffer.write(run_cgi())
