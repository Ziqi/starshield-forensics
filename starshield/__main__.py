#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Ziqi Xiao
# SPDX-License-Identifier: MIT
"""Module entry point enabling `python3 -m starshield <subcommand>`."""

from __future__ import annotations

from starshield.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
