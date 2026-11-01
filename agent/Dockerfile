FROM ubuntu:22.04

ARG WAZUH_VERSION=4.14.9
ENV DEBIAN_FRONTEND=noninteractive \
    WAZUH_MANAGER=wazuh.manager \
    WAZUH_AGENT_NAME=lab-agent-01

# A Linux endpoint with an SSH service to attack, a syslog daemon so sshd/useradd write
# /var/log/auth.log, iptables for Wazuh active response, and the Wazuh agent pinned to the
# same version as the manager (an agent must never be newer than its manager).
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl gnupg ca-certificates openssh-server rsyslog iptables procps sudo \
 && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends "wazuh-agent=${WAZUH_VERSION}-1" \
 && rm -rf /var/lib/apt/lists/*

# Container has no kernel log to read; sshd needs its privilege-separation directory.
RUN sed -i '/imklog/d' /etc/rsyslog.conf \
 && mkdir -p /run/sshd /lab/watched \
 && useradd -m -s /bin/bash labuser \
 && echo "labuser:$(head -c 24 /dev/urandom | base64)" | chpasswd \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
