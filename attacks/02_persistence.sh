#!/bin/bash
# Run on the lab agent as root. Simulates an intruder who already has a shell establishing persistence.
set -eu

# T1136.001 Create Account: Local Account
useradd -m -s /bin/bash svc_backup
echo "[agent] created local account svc_backup"

# T1053.003 Scheduled Task/Job: Cron. The command is inert: it only appends a line to a file.
echo '*/5 * * * * root echo "lab persistence marker" >> /tmp/lab-cron-marker' > /etc/cron.d/lab-persist
echo "[agent] wrote /etc/cron.d/lab-persist"

# Change to a file inside a watched directory.
echo "original" > /lab/watched/config.ini
sleep 2
echo "tampered" >> /lab/watched/config.ini
echo "[agent] modified /lab/watched/config.ini"
