#!/bin/bash
set -eu

# rsyslog drops to the syslog user, so the log must be owned by it or nothing is ever written.
install -o syslog -g adm -m 640 /dev/null /var/log/auth.log
rsyslogd
/usr/sbin/sshd

# Active response needs a working iptables; fall back to the legacy backend if nftables is unavailable.
if ! iptables -L >/dev/null 2>&1; then
  update-alternatives --set iptables /usr/sbin/iptables-legacy >/dev/null 2>&1 || true
fi

until /var/ossec/bin/agent-auth -m "$WAZUH_MANAGER" -A "$WAZUH_AGENT_NAME"; do
  echo "manager not ready for enrolment, retrying in 5s"
  sleep 5
done
sed -i "s|<address>.*</address>|<address>${WAZUH_MANAGER}</address>|" /var/ossec/etc/ossec.conf

/var/ossec/bin/wazuh-control start
exec tail -F /var/ossec/logs/ossec.log
