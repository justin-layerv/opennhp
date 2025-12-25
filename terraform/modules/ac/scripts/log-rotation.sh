#!/bin/bash
# Log rotation and disk cleanup for NHP AC instances
# Parameters are passed via SSM document
set -e

JOURNAL_MAX_SIZE="${JOURNAL_MAX_SIZE_MB:-100}"
LOG_RETENTION_DAYS="${LOG_RETENTION_DAYS:-7}"
NHP_AC_LOGS="${NHP_AC_LOGS_PATH:-/home/ubuntu/nhp-ac/logs}"

echo "=== Log Rotation and Disk Cleanup ==="
echo "Timestamp: $(date)"
echo "Journal max size: ${JOURNAL_MAX_SIZE}M"
echo "Log retention: ${LOG_RETENTION_DAYS} days"

# 1. Vacuum systemd journal
echo "Vacuuming systemd journal..."
journalctl --vacuum-size=${JOURNAL_MAX_SIZE}M

# 2. Clean package cache
echo "Cleaning package cache..."
if command -v apt-get &> /dev/null; then
  apt-get clean
elif command -v yum &> /dev/null; then
  yum clean all
fi

# 3. Remove old rotated logs
echo "Removing old rotated logs (>${LOG_RETENTION_DAYS} days)..."
find /var/log -type f -name '*.gz' -mtime +${LOG_RETENTION_DAYS} -delete 2>/dev/null || true
find /var/log -type f -name '*.[0-9]' -mtime +${LOG_RETENTION_DAYS} -delete 2>/dev/null || true

# 4. Truncate large SSM agent logs (>10MB, keep last 1000 lines)
for logfile in /var/log/amazon/ssm/*.log; do
  if [ -f "$logfile" ]; then
    size=$(stat -c%s "$logfile" 2>/dev/null || echo 0)
    if [ "$size" -gt 10485760 ]; then
      echo "Truncating $logfile (size: $size bytes)..."
      tail -1000 "$logfile" > "$logfile.tmp" && mv "$logfile.tmp" "$logfile"
    fi
  fi
done

# 5. Rotate NHP AC logs (>50MB, keep last 10000 lines)
if [ -d "$NHP_AC_LOGS" ]; then
  echo "Rotating NHP AC logs in $NHP_AC_LOGS..."
  for logfile in "$NHP_AC_LOGS"/*.log; do
    if [ -f "$logfile" ]; then
      size=$(stat -c%s "$logfile" 2>/dev/null || echo 0)
      if [ "$size" -gt 52428800 ]; then
        echo "Truncating $logfile (size: $size bytes)..."
        tail -10000 "$logfile" > "$logfile.tmp" && mv "$logfile.tmp" "$logfile"
      fi
    fi
  done
fi

# 6. Report disk usage
echo ""
echo "=== Disk Usage After Cleanup ==="
df -h /

echo ""
echo "Log rotation completed successfully"
