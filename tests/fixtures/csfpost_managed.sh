#!/bin/bash

# CSFV2-DOCKER-FORWARDING
# Preserve Docker bridge and Swarm overlay traffic when CSF reloads.
DOCKER_VERSION="$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)"
DOCKER_MAJOR="${DOCKER_VERSION%%.*}"
if [ "${DOCKER_MAJOR:-0}" -ge 28 ] && ! iptables -t filter -S DOCKER-FORWARD >/dev/null 2>&1; then
    systemctl restart docker >/dev/null 2>&1 || true
fi
DOCKER_IFACES="docker0 docker_gwbridge ingress"
for IFACE in $(ip -o link show 2>/dev/null | awk -F': ' '$2 ~ /^br-[[:xdigit:]]+$/ {print $2}'); do
    DOCKER_IFACES="$DOCKER_IFACES $IFACE"
done
for IFACE in $DOCKER_IFACES; do
    [ -d "/sys/class/net/$IFACE" ] || continue
    iptables -C FORWARD -i "$IFACE" -j ACCEPT 2>/dev/null || \
        iptables -I FORWARD 1 -i "$IFACE" -j ACCEPT
    iptables -C FORWARD -o "$IFACE" -j ACCEPT 2>/dev/null || \
        iptables -I FORWARD 1 -o "$IFACE" -j ACCEPT
    for SUBNET in $(ip -4 route show dev "$IFACE" scope link 2>/dev/null | awk '$1 ~ /^[0-9]+\./ {print $1}'); do
        iptables -t nat -C POSTROUTING -s "$SUBNET" ! -o "$IFACE" -j MASQUERADE 2>/dev/null || \
            iptables -t nat -A POSTROUTING -s "$SUBNET" ! -o "$IFACE" -j MASQUERADE
    done
done
# END CSFV2-DOCKER-FORWARDING

# csfv2-exposure:8080/tcp begin
iptables -I DOCKER-USER -p tcp -m conntrack --ctorigdstport 8080 --ctdir ORIGINAL -j DROP
iptables -I DOCKER-USER -p tcp -m conntrack --ctorigdstport 8080 --ctdir ORIGINAL -s 10.0.0.0/8 -j RETURN
# csfv2-exposure:8080/tcp end
