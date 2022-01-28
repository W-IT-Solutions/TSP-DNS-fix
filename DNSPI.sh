#!/bin/bash 
# shellcheck disable=SC2034,SC2015,SC2116
# Jan 6 2022 - scripting@waaromzomoeilijk.nl
# Install unbound as local dns cache server, let the system use that as its primary DNS and let unbound query DNS requests over all LTE interfaces
# This uses https://www.cloudflare.com/learning/dns/dns-over-tls/ (optional)
# Final speed tweaks will be added soon and this message will be removed.

################################ Logger
INTERACTIVE="0" # 1 Foreground / 0 = Background - Log all script output to file (0) or just output everything in stout (1)
if ! [ $INTERACTIVE == 1 ]; then 
    LOGFILE="/var/log/DNSPI.log" # Log file
    exec 3>&1 4>&2
    trap 'exec 2>&4 1>&3' 0 1 2 3 15 RETURN
    exec 1>>"$LOGFILE" 2>&1
fi

################################ Stock snippits
# Log line
# && success "$(date) -  - " || fatal "$(date) -  - "

################################ Variables and functions
# Dynamic
DEBUG="1" # 1 = on / 0 = off
MAINETHNIC="enp0s31f6" # Interface to ignore, please adjust, should be different on each system
APTIPV4="1" # Force APT to use IPV4, needed as IPV6 DNS lookups on LTE seem to fail (Note that IPV4 will still resolve both ipv4 and ipv6 addresses)
# Static
DATE=$(date +%d-%b-%Y-%H%M)
COUNTER="0"
MAINNIC=$(route -n | head -3 | tail -1 | awk '{printf "%s\n",$8}')
MAINIP=$(ip address show dev "$MAINNIC" | grep inet | head -1 | awk '{printf "%s\n",$2}' | sed 's|/24||g')

################################ CMD line output
print_text_in_color() {
/usr/bin/printf "%b%s%b\n" "$1" "$2" "$Color_Off"
}
Color_Off='\e[0m'       # Text Reset
IRed='\e[0;91m'         # Red
IGreen='\e[0;92m'       # Green
IYellow='\e[0;93m'      # Yellow
IBlue='\e[0;94m'        # Blue

success() {
	/bin/echo -e "${IGreen} $* ${Color_Off}" >&2
}
warning() {
	/bin/echo -e "${IYellow} $* ${Color_Off}" >&2
    	/bin/echo -e "${IYellow} $* ${Color_Off}" >> /var/log/health_check_script_errors_warnings.log 
    	COUNTER=$((COUNTER+1))       
}
error() {
	/bin/echo -e "${IRed} $* ${Color_Off}" >&2
  	/bin/echo -e "${IRed} $* ${Color_Off}" >> /var/log/health_check_script_errors_warnings.log
    	COUNTER=$((COUNTER+1))
}
header() {
	/bin/echo -e "${IBlue} $* ${Color_Off}" >&2
}
fatal() {
	/bin/echo -e "${IRed} $* ${Color_Off}" >&2
    	/bin/echo -e "${IRed} $* ${Color_Off}" >> /var/log/health_check_script_errors_warnings.log    
	exit 1
}

################################ Root check
is_root() {
	if [[ "$EUID" -ne 0 ]];	then
		return 1
	else
		return 0
	fi
}

root_check() {
	if ! is_root; then
		fatal "$(date) - INIT - Failed, script needs sudo permissions to function right now"
	fi
}

################################ Debug mode, script stops when a commands errors out
debug_mode() {
	if [ "$DEBUG" -eq 1 ]; then
		set -ex && success "$(date) - INIT - Debug set" || error "$(date) - INIT - Setting debug failed"
	fi
}

################################ Get all interfaces to use (excluding tun tap etc)
# ip l | awk -F ":" '/^[0-9]+:/{dev=$2 ; if ( dev !~ /^ lo$/) {print $2}}'
get_interfaces(){
    readarray -t interfaces < <(ip l | grep enp | grep -v "$MAINETHNIC" |  awk '{printf "%s\n",$2}' | sed 's/://g' | sed -r '/^\s*$/d' | cut -f1 -d"@")
    for i in "${interfaces[@]// /}" ; do 
        echo "$i" >> /tmp/interfaces && success "$(date) - get_interfaces - Found interface: $i"
    done
}

################################ Hardcode outgoing interfaces in unbound config
set_outgoing_interfaces_unbound(){
    readarray -t interfaces < <(cat /tmp/interfaces)
    for INTERFACE in "${interfaces[@]// /}" ; do 
        IP=$(ip address show dev "$INTERFACE" | grep inet | head -1 | awk '{printf "%s\n",$2}' | sed 's|/24||g')
        if [ -z "$IP" ]; then
            error "$(date) - Setup Unbound - No IP on $INTERFACE"
        else
            echo "outgoing-interface: $IP" >> /etc/unbound/outgoing.conf
        fi
    done
}

################################ Pre init
header "Pre init $(date)"
debug_mode
root_check && success "$(date) - INIT - Root check ok"

################################ Update and upgrade
header "Update & upgrade $(date)"
apt update && success "$(date) - update - Updated" || fatal "$(date) - update - Failed to update"
apt full-upgrade -y && success "$(date) - full-upgrade - Upgraded" || fatal "$(date) - full-upgrade - Failed to upgrade"
header "Dependencies $(date)"
apt install -y unbound dnsutils curl && success "$(date) - Dependancies - Installed" || fatal "$(date) - Dependancies - Failed to install"

################################ Get all valid interfaces to setup for dpinger monitoring 
header "$(date) - Get all interfaces"
cat /dev/null > /tmp/interfaces && success "$(date) - Get all interfaces - Cleared temp file" || fatal "$(date) - Get all interfaces - Failed to clear temp file"
get_interfaces

################################ Create scripts dir
mkdir -p /var/scripts && success "$(date) - Create DIRs - Scripts dir created"

################################ Fix: dhcpcd[5131]: script_runreason: control_queue: No buffer space available
if [ -f /proc/sys/net/core/wmem_max ]; then
    cp /proc/sys/net/core/wmem_max /proc/sys/net/core/wmem_max.backup."$DATE" && success "$(date) - Increase buffer space - Backup wmem_max" || error "$(date) - Increase buffer space - Failed to backup wmem_max"
    echo "638976" > /proc/sys/net/core/wmem_max && success "$(date) - Increase buffer space - wmem_max set to 638976, 3 times its original value" || error "$(date) - Increase buffer space - Failed to set wmem_max"
else
    warning "$(date) - Increase buffer space - wmem_max not present"
fi

################################ Disable listening of resolved on port 53 and set dns server to unbound and have cloudflare as fallback IP in case unbound is unreachable
cp /etc/systemd/resolved.conf /etc/systemd/resolved.conf.backup."$DATE" && success "$(date) - Resolved - Config backed up" || fatal "$(date) - Resolved - Failed to backup config"

# The DNSStubListener directive is essential to ensure it does not listen for DNS queries.
# You may actually want MulticastDNS if you do not use avahi-daemon for multicast-DNS purpose
cat > /etc/systemd/resolved.conf <<EOF && success "$(date) - Resolved - New config set" || fatal "$(date) - Resolved - Failed to set new config"
[Resolve]
DNS=127.0.0.1
FallbackDNS=1.0.0.1
MulticastDNS=no
DNSStubListener=no
EOF

systemctl restart systemd-resolved.service && success "$(date) - Resolved - Restarted service" || fatal "$(date) - Resolved - Failed to restart service"

################################ Check resolv.conf, needs to be updated by resolved automagically
if grep -qrnw -e 'nameserver 127.0.0.1' /etc/resolv.conf ; then 
    warning "$(date) - Resolvconf - 127.0.0.1 is already present in /etc/resolv.conf"  
else 
    mv /etc/resolvconf.conf /etc/resolvconf.conf.backup."$DATE"
    echo "nameserver 127.0.0.1" > /etc/resolv.conf && success "$(date) - Resolvconf - Set 127.0.0.1 as nameserver in /etc/resolv.conf" || warning "$(date) - Resolvconf - Failed to set 127.0.0.1 as nameserver in /etc/resolv.conf"
fi
################################ Setup Unbound
crontab -l | { cat; echo "$CRON /bin/bash $SCRIPTS/$SCRIPTNAME.sh > /dev/null 2>&1"; } | crontab - 

if ! crontab -l | grep "root.hints"; then
    # Cronjob check
        crontab -l | { cat; echo '0 */6 * * * /usr/bin/curl -o "/etc/unbound/root.hints" "https://www.internic.net/domain/named.cache"'; } | crontab - && success "$(date) - Setup Unbound - Wrote unbound root.hints" || fatal "$(date) - Setup Unbound - Failed to write unbound root.hints"
fi

cat > /etc/unbound/unbound.conf <<EOF && success "$(date) - Setup Unbound - Wrote unbound config" || fatal "$(date) - Setup Unbound - Failed to write unbound config"
include: "/etc/unbound/unbound.conf.d/*.conf"

server:
    # If no logfile is specified, syslog is used
    logfile: "/var/log/unbound/unbound.log"
    verbosity: 5
    
    # Interface to use to connect to the network. This interface is used to send queries to authoritative servers and receive their replies. 
    # Can be given multiple times to work on several interfaces. If none are given the default (all) is used. 
    # outgoing-interface: <ip address or ip6 netblock>
    include: "/etc/unbound/outgoing.conf"

    # You can specify the same interfaces in interface: and outgoing-interface: lines, the interfaces are then used for both purposes. 
    interface: 0.0.0.0
    #interface: ::0
    #interface: 127.0.0.1
    port: 53
    do-ip4: yes
    do-udp: yes
    do-tcp: yes

    # May be set to yes if you have IPv6 connectivity
    do-ip6: no

    # You want to leave this to no unless you have *native* IPv6. With 6to4 and
    # Terredo tunnels your web browser should favor IPv4 for the same reasons
    prefer-ip6: no

    # Use this only when you downloaded the list of primary root servers!
    root-hints: "/etc/unbound/root.hints"

    # Trust glue only if it is within the server's authority
    harden-glue: yes

    # Require DNSSEC data for trust-anchored zones, if such data is absent, the zone becomes BOGUS
    harden-dnssec-stripped: yes

    # Don't use Capitalization randomization as it known to cause DNSSEC issues sometimes
    # see https://discourse.pi-hole.net/t/unbound-stubby-or-dnscrypt-proxy/9378 for further details
    use-caps-for-id: no

    # Reduce EDNS reassembly buffer size.
    # Suggested by the unbound man page to reduce fragmentation reassembly problems
    edns-buffer-size: 1472

    # Perform prefetching of close to expired message cache entries
    # This only applies to domains that have been frequently queried
    prefetch: yes
    prefetch-key: yes

    # One thread should be sufficient, can be increased on beefy machines. In reality for most users running on small networks or on a single machine, it should be unnecessary to seek performance enhancement by increasing num-threads above 1.
    num-threads: 2

    # Ensure kernel buffer is large enough to not lose messages in traffic spikes
    so-rcvbuf: 1m

    # Ignore very large queries.
    harden-large-queries: yes

    # Perform additional queries for infrastructure data to harden the referral
    # path. Validates the replies if trust anchors are configured and the zones
    # are signed. This enforces DNSSEC validation on nameserver NS sets and the
    # nameserver addresses that are encountered on the referral path to the 
    # answer. Experimental option.
    harden-referral-path: no

    # Ignore very small EDNS buffer sizes from queries.
    harden-short-bufsize: yes

    # Refuse id.server and hostname.bind queries
    hide-identity: yes

    # Refuse version.server and version.bind queries
    hide-version: yes

    # Report this identity rather than the hostname of the server.
    identity: "DNS"

    # Misc
    qname-minimisation: yes
    use-caps-for-id: yes
    cache-min-ttl: 0
    serve-expired: yes
    msg-cache-size: 128m
    msg-cache-slabs: 8
    rrset-roundrobin: yes
    rrset-cache-size: 256m
    rrset-cache-slabs: 8
    key-cache-size: 256m
    key-cache-slabs: 8

    # These private network addresses are not allowed to be returned for public
    # internet names. Any  occurrence of such addresses are removed from DNS
    # answers. Additionally, the DNSSEC validator may mark the  answers  bogus.
    # This  protects  against DNS  Rebinding
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8
    private-address: fd00::/8
    private-address: fe80::/10

    tls-cert-bundle: /etc/ssl/certs/ca-certificates.crt
    
forward-zone:
    name: "."
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
    forward-addr: 1.0.0.1@853#cloudflare-dns.com
    forward-ssl-upstream: yes
EOF

# Add all available NICs as outbound interface for unbound
if [ -f /etc/unbound/outgoing.conf ]; then
    rm -rf /etc/unbound/outgoing.conf 
fi

set_outgoing_interfaces_unbound

systemctl enable unbound.service && success "$(date) - Setup Unbound - Enabled service" || fatal "$(date) - Setup Unbound - Failed to enable service"
systemctl restart unbound.service && success "$(date) - Setup Unbound - Restarted service" || fatal "$(date) - Setup Unbound - Failed to restart service"

################################ DNS check loopback -> unbound cache/forward
# Clear current DNS cache
systemd-resolve --flush-caches && success "$(date) - DNS Check - Flush DNS" || fatal "$(date) - DNS Check - Flushing DNS failed"

if host google.com 127.0.0.1; then
    success "$(date) - DNS Check - DNS is working via 127.0.0.1 to unbound!"
else
    fatal "$(date) - DNS Check - DNS is not working via 127.0.0.1 to unbound!"
fi

################################  Misc
header "$(date) - Misc"
service unbound* restart

if [ "$APTIPV4" == "ON" ]; then
    echo 'Acquire::ForceIPv4 “true”;' > /etc/apt/apt.conf.d/99force-ipv4 && success "$(date) - Misc - Force APT to use IPV4" || fatal "$(date) - Misc - Failed to force APT to use IPV4"
fi

# End of script
success "$(date) - Script finished - $COUNTER Warning(s) and / or error(s)"
cat /var/log/health_check_script_errors_warnings.log

exit 0
