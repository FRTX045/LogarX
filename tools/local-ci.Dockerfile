# The Linux machine tools/local-ci.sh runs its Linux jobs in: CI's ubuntu-latest,
# as near as an image gets.
#
# ubuntu-latest is Ubuntu 24.04 until GitHub moves it to 26.04 on 2026-10-19;
# change the base here when it does, so the two stay one system.
ARG PY=3.12
FROM golang:1.25-bookworm AS go
FROM ghcr.io/astral-sh/uv:latest AS uv

FROM ubuntu:24.04
ARG PY
COPY --from=go /usr/local/go /usr/local/go
COPY --from=uv /uv /uvx /usr/local/bin/
ENV PATH=/venv/bin:/usr/local/go/bin:$PATH \
    VIRTUAL_ENV=/venv \
    UV_LINK_MODE=copy \
    DEBIAN_FRONTEND=noninteractive
# The workflow's list (libegl1 libgl1 libxkbcommon-x11-0 libdbus-1-3), plus what
# the GitHub runner image already carries and a bare ubuntu:24.04 does not:
# glib, fontconfig, freetype, and git for the test that asks `git ls-files`.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libegl1 libgl1 libxkbcommon-x11-0 libdbus-1-3 \
      libxkbcommon0 libglib2.0-0t64 libfontconfig1 libfreetype6 \
      git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
# The interpreter only. The project and its dependencies go into this empty
# environment on every run, so a dependency pyproject.toml forgot to declare
# fails here as it would on a fresh runner.
RUN uv venv --managed-python --python "$PY" /venv
