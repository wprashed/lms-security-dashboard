#!/bin/bash
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
DIR="/Users/rashed/lms-security-dashboard"
cd "$DIR" || exit 1

mkdir -p "$DIR/logs"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] === Launching Daily LMS Security Sync ===" >> "$DIR/logs/update.log"
/usr/bin/python3 "$DIR/scripts/update_pipeline.py" > /dev/null 2>&1
EXIT_CODE=$?
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Daily LMS Security Sync completed with exit code: $EXIT_CODE" >> "$DIR/logs/update.log"
exit $EXIT_CODE
