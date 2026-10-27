#!/bin/sh
# Print the last rebuild failure, if there was one.
#
# Sourced by the hooks that run often, so the news reaches whoever is working
# here without anything to open. `packaging/rebuild.py` writes the marker when
# a build fails and removes it when the next one succeeds, so this cannot nag
# about a fault that has already been fixed.
_marker="$(git rev-parse --git-dir 2>/dev/null)/logarx-build-failed"
if [ -f "$_marker" ]; then
    printf '\033[31m[logarx] dist/ was NOT rebuilt: %s\033[0m\n' "$(cat "$_marker")"
    printf '\033[31m         the previous application is still there and still runs.\033[0m\n'
    printf '         retry: python packaging/rebuild.py\n'
fi
