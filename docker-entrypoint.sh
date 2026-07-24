#!/bin/sh
set -e

# Route CLI commands and flags to the Python CLI
case "$1" in
  scan|list|dashboard|init|plugin|--version|--help|-h)
    exec python cli.py "$@"
    ;;
  *)
    # Allow running arbitrary commands (python, bash, etc.)
    exec "$@"
    ;;
esac
