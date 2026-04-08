#!/bin/bash
CURRENT_DIR=$(cd "$(dirname "$0")" && pwd)
if [ "$1" = "-f" ];then
    echo "Flushing existing iptables rules..."
    # Set DROP policy first to avoid exposure window during flush
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -F
    iptables -X
    # Flush ipsets to clear previously authorized tuples
    ipset flush 2>/dev/null || true
    ipset destroy 2>/dev/null || true
    # Flush IPv6 rules as well
    if which ip6tables > /dev/null 2>&1; then
        ip6tables -P INPUT DROP
        ip6tables -P FORWARD DROP
        ip6tables -F
        ip6tables -X
    fi
fi
### ipset (IPv4) ###
echo "Setting up IPv4 ipset"
echo ""
ipset -exist create defaultset hash:ip,port,ip counters maxelem 1000000 timeout 120
ipset -exist create defaultset_down hash:ip,port,ip counters maxelem 1000000 timeout 121
ipset -exist create tempset hash:net,port counters maxelem 1000000 timeout 5
echo ""
echo "Setting IPv4 ipset OK ..."

### ipset (IPv6) ###
IP6TABLES=$(which ip6tables 2>/dev/null)
IPSET6_OK=0
if [ -n "$IP6TABLES" ]; then
    echo "Setting up IPv6 ipset"
    ipset -exist create defaultset_v6 hash:ip,port,ip family inet6 counters maxelem 1000000 timeout 120 2>/dev/null || true
    ipset -exist create defaultset_down_v6 hash:ip,port,ip family inet6 counters maxelem 1000000 timeout 121 2>/dev/null || true
    ipset -exist create tempset_v6 hash:net,port family inet6 counters maxelem 1000000 timeout 5 2>/dev/null || true

    # Verify IPv6 ipset creation
    IPSET6_OK=1
    ipset list defaultset_v6 > /dev/null 2>&1 || IPSET6_OK=0
    if [ $IPSET6_OK -eq 1 ]; then
        echo "Setting IPv6 ipset OK ..."
    fi
fi

### IPv4 iptables rules (applied atomically via iptables-restore) ###
echo "Applying IPv4 iptables rules atomically ..."
echo ""

if ! iptables-restore <<'IPTABLES_RULES'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:NHP_DENY - [0:0]
-A NHP_DENY -j LOG --log-prefix "[NHP-DENY] " --log-level 6 --log-ip-options
-A NHP_DENY -j DROP
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state ESTABLISHED -j ACCEPT
-A INPUT -m set --match-set tempset src,dst -j SET --add-set defaultset src,dst,dst
-A INPUT -m set --match-set defaultset src,dst,dst -j SET --add-set defaultset_down src,dst,dst
-A INPUT -m set --match-set defaultset src,dst,dst -j LOG --log-prefix "[NHP-ACCEPT] " --log-level 6 --log-ip-options
-A INPUT -m set --match-set defaultset src,dst,dst -j ACCEPT
-A INPUT -m set --match-set tempset src,dst -j ACCEPT
-A INPUT -j NHP_DENY
-A FORWARD -m set --match-set defaultset src,dst,dst -j SET --add-set defaultset_down src,dst,dst
-A FORWARD -m set --match-set defaultset src,dst,dst -j LOG --log-prefix "[NHP-FORWARD] " --log-level 6 --log-ip-options
-A FORWARD -m set --match-set defaultset src,dst,dst -j ACCEPT
-A FORWARD -m state --state ESTABLISHED -j ACCEPT
-A FORWARD -j NHP_DENY
COMMIT
IPTABLES_RULES
then
    echo "ERROR: iptables-restore failed — new IPv4 rules not applied, previous rules retained"
    exit 1
fi

echo "Setting IPv4 iptables OK ..."

### IPv6 firewall rules ###
if [ -n "$IP6TABLES" ] && [ $IPSET6_OK -eq 1 ]; then
    echo "Applying IPv6 iptables rules atomically ..."

    if ! ip6tables-restore <<'IP6TABLES_RULES'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:NHP_DENY - [0:0]
-A NHP_DENY -j LOG --log-prefix "[NHP-DENY6] " --log-level 6 --log-ip-options
-A NHP_DENY -j DROP
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state ESTABLISHED -j ACCEPT
-A INPUT -m set --match-set tempset_v6 src,dst -j SET --add-set defaultset_v6 src,dst,dst
-A INPUT -m set --match-set defaultset_v6 src,dst,dst -j SET --add-set defaultset_down_v6 src,dst,dst
-A INPUT -m set --match-set defaultset_v6 src,dst,dst -j LOG --log-prefix "[NHP-ACCEPT6] " --log-level 6 --log-ip-options
-A INPUT -m set --match-set defaultset_v6 src,dst,dst -j ACCEPT
-A INPUT -m set --match-set tempset_v6 src,dst -j ACCEPT
-A INPUT -j NHP_DENY
-A FORWARD -m set --match-set defaultset_v6 src,dst,dst -j SET --add-set defaultset_down_v6 src,dst,dst
-A FORWARD -m set --match-set defaultset_v6 src,dst,dst -j LOG --log-prefix "[NHP-FORWARD6] " --log-level 6 --log-ip-options
-A FORWARD -m set --match-set defaultset_v6 src,dst,dst -j ACCEPT
-A FORWARD -m state --state ESTABLISHED -j ACCEPT
-A FORWARD -j NHP_DENY
COMMIT
IP6TABLES_RULES
    then
        echo "ERROR: ip6tables-restore failed — new IPv6 rules not applied, previous rules retained"
        exit 1
    fi

    echo "Setting IPv6 iptables OK ..."
fi

### iptables kernel logging ###
if [ -d /etc/rsyslog.d ] && [ ! -f /etc/rsyslog.d/10-nhplog.conf ]; then
    echo "Setting up rsyslog ..."
    mkdir -p logs
    chmod -R 777 logs/
    echo ":msg,contains,\"[NHP-ACCEPT\" -$CURRENT_DIR/logs/nhp_accept.log

& stop
:msg,contains,\"[NHP-FORWARD\" -$CURRENT_DIR/logs/nhp_forward.log

& stop
:msg,contains,\"[NHP-DENY\" -$CURRENT_DIR/logs/nhp_deny.log

& stop" > /etc/rsyslog.d/10-nhplog.conf
    systemctl restart rsyslog
fi

echo "Setting iptables default OK ..."
echo ""
### EOF ###
