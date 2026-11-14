#!/bin/bash -eu
# SPDX-FileCopyrightText: 2026 Ziqi Xiao
# SPDX-License-Identifier: MIT

SITE_PKGS="$(python3 -c 'import site; print(site.getsitepackages()[0])')"
cp -r "$SRC/starshield-forensics/starshield" "$SITE_PKGS/"
compile_python_fuzzer "$SRC/starshield-forensics/tests/fuzz_parsers.py"
