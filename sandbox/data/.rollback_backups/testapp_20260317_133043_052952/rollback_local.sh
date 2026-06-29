#!/usr/bin/env bash
set -e
echo "== Rolling back to local backup =="
if [ -f app.txt.bak ]; then
  cp app.txt.bak app.txt
  cp version.txt.bak version.txt
  echo "Rolled back to:"
  cat version.txt
  cat app.txt
else
  echo "No local backup found. Cannot rollback."
  exit 1
fi
