#!/bin/sh
set -e

# If first arg is a known CLI command, run it
case "$1" in
  scan|list|dashboard|init|plugin)
    exec python cli.py "$@"
    ;;
  *)
    # Allow running arbitrary commands (python, bash, etc.)
    exec "$@"
    ;;
esac
