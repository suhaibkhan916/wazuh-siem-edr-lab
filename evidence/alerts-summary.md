# Alerts raised for lab-agent-01

225 alerts across 14 rules, from the manager's `alerts.json`.

| Rule | Level | Alerts | ATT&CK | Description |
|---:|---:|---:|---|---|
| 100100 | 12 | 1 | T1053.003 | Lab: file added under /etc/cron.d (possible cron persistence) |
| 2502 | 10 | 2 | T1110 | syslog: User missed the password more than one time |
| 5763 | 10 | 1 | T1110 | sshd: brute force trying to get access to the system. Authentication failed. |
| 5901 | 8 | 1 | - | New group added to the system. |
| 5902 | 8 | 1 | T1136 | New user added to the system. |
| 19007 | 7 | 87 | - | CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0.: Ensure /tmp is a separate partition. |
| 550 | 7 | 1 | T1565.001 | Integrity checksum changed. |
| 19003 | 5 | 1 | - | SCA summary: CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0.: Score less than 80% (50) |
| 554 | 5 | 1 | - | File added to the system. |
| 5760 | 5 | 7 | T1110.001, T1021.004 | sshd: authentication failed. |
| 19008 | 3 | 89 | - | CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0.: Ensure nodev option set on /dev/shm partition. |
| 19009 | 3 | 31 | - | CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0.: Ensure bootloader password is set. |
| 501 | 3 | 1 | - | New wazuh agent connected. |
| 651 | 3 | 1 | - | Host Blocked by firewall-drop Active Response |
