#!/usr/bin/env bash
# wrapper for cleanup job images (keeps secrets out of crontab)
export DB_HOST="localhost"
export DB_USER="shieldpatch_user"
export DB_PASS="ajaykumar@040702"
export DB_NAME="ShieldPatch"
# path to your venv python
VENV="/Users/ajaykumar/Desktop/ShieldPatch/backend/venv310/bin/python"
SCRIPT="/Users/ajaykumar/Desktop/ShieldPatch/backend/scripts/cleanup_job_images.py"

# run (delete images older than 30 days)
$VENV $SCRIPT --days 30 --db-host $DB_HOST --db-user $DB_USER --db-pass "$DB_PASS" --db-name "$DB_NAME" --pattern "shieldpatch/sandbox:job-"