#!/bin/sh

# Allow NetBird forwarding
iptables -I FORWARD 1 -i wt0 -j ACCEPT
iptables -I FORWARD 1 -o wt0 -m state --state ESTABLISHED,RELATED -j ACCEPT

# NAT NetBird CGNAT range
iptables -t nat -A POSTROUTING -s 100.0.0.0/8 -o enp3s0 -j MASQUERADE




#ipv6
# Allow NetBird forwarding
ip6tables -I FORWARD 1 -i wt0 -j ACCEPT
###ip6tables -I FORWARD 1 -o wt0 -m state --state ESTABLISHED,RELATED -j ACCEPT

# NAT NetBird CGNAT range
##ip6tables -t nat -A POSTROUTING -s 100.0.0.0/8 -o eth0 -j MASQUERADE


#8096 to home Jellyfin
<<COMMENT
iptables -t nat -A PREROUTING \
  -i enp3s0 \
  -p tcp --dport 8096 \
  -j DNAT --to-destination 10.12.10.12:8096

iptables -A FORWARD \
  -i enp3s0 -o wt0 \
  -p tcp -d 10.12.10.12 --dport 8096 \
  -m state --state NEW,ESTABLISHED,RELATED \
  -j ACCEPT

iptables -A FORWARD \
  -i wt0 -o enp3s0 \
  -p tcp -s 10.12.10.12 --sport 8096 \
  -m state --state ESTABLISHED,RELATED \
  -j ACCEPT

#iptables -t nat -A POSTROUTING \
#  -o wt0 \
#  -p tcp -d 10.12.10.12 --dport 8096 \
#  -j MASQUERADE
echo "Script finished."
COMMENT

# Allow NetBird forwarding
###iptables -I FORWARD 1 -i wt0 -j ACCEPT
###iptables -I FORWARD 1 -o wt0 -m state --state ESTABLISHED,RELATED -j ACCEPT

# NAT NetBird CGNAT range
###iptables -t nat -A POSTROUTING -s 100.0.0.0/8 -o ens3 -j MASQUERADE




# BEGIN UCM6302 OpenVPN (public IPv6 for VoIP)
UCM6=2602:ff16:13:0:1:186:5060:5060
iptables  -I OUTPUT 1 -p udp --sport 1194 -j ACCEPT
ip6tables -I OUTPUT 1 -p udp --sport 1194 -j ACCEPT
iptables  -I INPUT  1 -i tun-ucm -j ACCEPT
iptables  -I OUTPUT 1 -o tun-ucm -j ACCEPT
ip6tables -I INPUT  1 -i tun-ucm -p ipv6-icmp -j ACCEPT
ip6tables -I OUTPUT 1 -o tun-ucm -j ACCEPT
ip6tables -N UCMFWD 2>/dev/null || ip6tables -F UCMFWD
ip6tables -A UCMFWD -i tun-ucm -o enp3s0 -s $UCM6 -j ACCEPT
ip6tables -A UCMFWD -i enp3s0 -o tun-ucm -d $UCM6 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip6tables -A UCMFWD -i enp3s0 -o tun-ucm -d $UCM6 -p ipv6-icmp -j ACCEPT
ip6tables -A UCMFWD -i enp3s0 -o tun-ucm -d $UCM6 -p udp --dport 5060:5062 -j ACCEPT
ip6tables -A UCMFWD -i enp3s0 -o tun-ucm -d $UCM6 -p tcp --dport 5060:5062 -j ACCEPT
ip6tables -A UCMFWD -i enp3s0 -o tun-ucm -d $UCM6 -p udp --dport 10000:20000 -j ACCEPT
ip6tables -A UCMFWD -i enp3s0 -o tun-ucm -d $UCM6 -p tcp -m multiport --dports 8089,8090 -j ACCEPT
#ip6tables -A UCMFWD -i enp3s0 -o tun-ucm -d $UCM6 -p tcp -m multiport --dports 8090 -j ACCEPT
ip6tables -A UCMFWD -i tun-ucm -j DROP
ip6tables -A UCMFWD -o tun-ucm -j DROP
ip6tables -I FORWARD 1 -j UCMFWD
# END UCM6302 OpenVPN

netbird down;
netbird up  --allow-server-ssh --enable-ssh-root;
