# Incident ticket: SSH brute force followed by persistence on lab-agent-01

Written the way a Tier 1/2 analyst would hand a case on. Every timestamp and rule below comes from the manager's `alerts.json` for one run of `python lab.py attack` (see [`evidence/`](../evidence)). The activity is **simulated** inside the lab's own containers.

| Field | Value |
|---|---|
| Severity | High (highest alert level 12) |
| Host | `lab-agent-01` (Ubuntu 22.04, Wazuh agent 4.14.9) |
| Source of attack | `172.19.0.6` (private lab network) |
| Status | Contained automatically; remediation steps below are pending |

## Summary

An external host guessed passwords for the `labuser` SSH account until Wazuh's brute-force rule fired, and the manager automatically blocked the source address at the host firewall. Seconds-to-minutes later, new artefacts appeared on the host consistent with an intruder establishing persistence: a new local account, a cron file, and a changed file in a monitored directory. In the simulation the brute force never succeeded, so the persistence activity represents what would follow a different, successful intrusion. A real case would need that initial-access gap explained before closing.

## Timeline (UTC, 2026-11-01)

| Time | Rule | Level | Event | ATT&CK |
|---|---|---:|---|---|
| 16:26:12.023 | 5760 | 5 | First `sshd: authentication failed` for `labuser` from 172.19.0.6 | T1110.001 |
| 16:26:16.027 | **5763** | 10 | `sshd: brute force trying to get access to the system` (8 failures, same source) | T1110 |
| 16:26:16 | - | - | `firewall-drop` runs on the agent (`active-responses.log`) | - |
| 16:26:18.025 | 651 | 3 | `Host Blocked by firewall-drop Active Response` for 172.19.0.6 | - |
| 16:26:18.040 | 2502 | 10 | `User missed the password more than one time` | T1110 |
| 16:26:31.529 | **100100** | 12 | Custom rule: file added under `/etc/cron.d` (`/etc/cron.d/lab-persist`) | T1053.003 |
| 16:26:32.024 | 5902 | 8 | `New user added to the system` (`svc_backup`) | T1136 |
| 16:26:32.024 | 5901 | 8 | `New group added to the system` | - |
| 16:26:33.751 | 550 | 7 | `Integrity checksum changed` on `/lab/watched/config.ini` | T1565.001 |

Detection to containment: about **4 seconds** from the first failed-login alert to the firewall action. The cron alert arrived in the same second the file was written, because that directory is monitored in real time (see `config/agent.conf`).

## Analysis

- The brute force is unambiguous: seven rule-5760 failures from one address inside a few seconds, escalating to 5763.
- The containment worked: the agent's INPUT chain gained `-A INPUT -s 172.19.0.6/32 -j DROP` and a connection attempt from the attacker to port 22 then timed out (`evidence/agent-iptables.txt`).
- The block is **temporary by design**: 180 seconds, then Wazuh removes the rule. It buys response time; it is not remediation.
- Rule 100100 is local detection engineering. Built-in rule 554 only says "file added" at level 5. Narrowing it to `/etc/cron.d` and raising it to level 12 is what makes it a page-worthy alert (see `config/local_rules.xml`).
- The Wazuh built-in SCA (CIS benchmark) generated about 200 low-level alerts on first start. They are noise for this case and are why the alert summary shows 14 rules for a handful of attacker actions.

## Indicators

| Type | Value |
|---|---|
| Source IP | 172.19.0.6 |
| Targeted account | `labuser` (SSH password authentication) |
| New account | `svc_backup` |
| Persistence file | `/etc/cron.d/lab-persist` |
| Modified file | `/lab/watched/config.ini` |

## Recommended follow-up

1. Disable and investigate `svc_backup`; confirm who created it and from which session.
2. Remove `/etc/cron.d/lab-persist` after capturing its contents and hash.
3. Disable SSH password authentication on the host; require keys.
4. Search other agents' `auth.log` data for the same source address.
5. Decide whether a 180-second block is enough or whether the source should be blocked at a network boundary.
