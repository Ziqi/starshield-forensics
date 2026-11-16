# SPDX-FileCopyrightText: 2026 Ziqi Xiao
# SPDX-License-Identifier: MIT

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

COPY --chown=65532:65532 LICENSE README.md pyproject.toml /app/
COPY --chown=65532:65532 starshield /app/starshield

USER 65532:65532

ENTRYPOINT ["python3", "-m", "starshield.cli", "mcp"]
