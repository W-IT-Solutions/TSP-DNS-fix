#!/bin/bash 
# shellcheck disable=SC2034,SC2015,SC2116,SC2002
# Jan 6 2022 - scripting@waaromzomoeilijk.nl
# Install unbound as local dns cache server, let the system use that as its primary DNS and let unbound query DNS requests over all LTE interfaces
# This uses https://www.cloudflare.com/learning/dns/dns-over-tls/ (optional)
#
# Unbound needs to build up a cache of results before it starts to speed up.
# When you browse websites you make dozens of DNS queries for different resources (JavaScript, CSS, etc). 
# Lots of these libraries are commonly used across multiple websites.
# Unbound will soon learn where those resources are and won't have to do a full lookup every time.
#
# On the side this will also install systemd scripts for each interface to use for monitoring the LTE endpoint link state
# Since the system with no MAIN Ethernet (or with for that matter) land line is not automatically switching based upon interface health
# Therefore if interface is really down, remove it from unbound's 'outgoing-interface' config and reload. While preserving the cache (plus extra dump in redis for persistant cache)
#
###############################################################################################################
# LOGGER                                                                                                      #
###############################################################################################################
INTERACTIVE="0" # 1 Foreground / 0 = Background - Log all script output to file (0) or just output everything in stout (1)
if [ $INTERACTIVE == 0 ]; then 
    LOGFILE="/var/log/DNS_fix_install.log" # Log file
    exec 3>&1 4>&2
    trap 'exec 2>&4 1>&3' 0 1 2 3 15 RETURN
    exec 1>>"$LOGFILE" 2>&1
fi
cat /dev/null > /var/log/health_check_script_errors_warnings.log && echo "$(date) - INIT - Cleaned error/warning log" || echo "$(date) - INIT - Failed to clean error/wrning log"

###############################################################################################################
# DEFAULT LOG EXTENSION                                                                                       #
###############################################################################################################
# && success "$(date) -  - " || fatal "$(date) -  - "

###############################################################################################################
# VARIABLES                                                                                                   #
###############################################################################################################

###############
##### DYNAMIC #
###############
VERSION="0.2"
DEBUG="1" # 1 = on / 0 = off
SCRIPTS="/var/scripts" # Directory to place scripts beloning to this project
MAINETHNIC="enp0s31f6" # Interface to ignore, please adjust, should be different on each system
APTIPV4="1" # Force APT to use IPV4, needed as IPV6 DNS lookups on LTE seem to fail (Note that IPV4 will still resolve both ipv4 and ipv6 addresses)
LOSS="15" # Trigger interface removal from unbound outgoing config, at % loss
#LATENCY="200m" # latency threshold in ms, use only m as in NUMBERm and not NUMBERms in var.
#TIME="10" # 10 Seconds measure period for dpinger

###############
##### STATIC  #
###############
DATE=$(date +%d-%b-%Y-%H%M)
COUNTER="0"
MAINNIC=$(route -n | head -3 | tail -1 | awk '{printf "%s\n",$8}')
MAINIP=$(ip address show dev "$MAINNIC" | grep inet | head -1 | awk '{printf "%s\n",$2}' | sed 's|/24||g')

###############################################################################################################
# CMD LINE OUTPUT                                                                                             #
###############################################################################################################
Color_Off='\e[0m'       # Text Reset
IRed='\e[0;91m'         # Red
IGreen='\e[0;92m'       # Green
IYellow='\e[0;93m'      # Yellow
IBlue='\e[0;94m'        # Blue

print_text_in_color() {
	/usr/bin/printf "%b%s%b\n" "$1" "$2" "$Color_Off"
}
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

###############################################################################################################
# ROOT CHECK                                                                                                  #
###############################################################################################################
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

###############################################################################################################
# DEBUG                                                                                                       #
###############################################################################################################
debug_mode() {
	if [ "$DEBUG" -eq 1 ]; then
		set -ex && success "$(date) - INIT - Debug set" || error "$(date) - INIT - Setting debug failed"
	fi
}

###############################################################################################################
# GET ALL ENP* INTERFACES EXCLUDING $MAINETHNIC AND LOOPBACK                                                  #
###############################################################################################################
get_interfaces() {
    readarray -t interfaces < <(ip l | grep enp | grep -v "$MAINETHNIC" | awk '{printf "%s\n",$2}' | sed 's/://g' | sed -r '/^\s*$/d' | cut -f1 -d"@")
    for i in "${interfaces[@]// /}" ; do 
        echo "$i" >> /tmp/interfaces && success "$(date) - get_interfaces - Found interface: $i"
    done
}

###############################################################################################################
# SET OUTGOING INTERFACE >> UNBOUND.CONF                                                                      #
###############################################################################################################
set_outgoing_interfaces_unbound() {
    readarray -t interfaces < <(cat /tmp/interfaces)
    for INTERFACE in "${interfaces[@]// /}" ; do 
        IP=$(ip address show dev "$INTERFACE" | grep inet | head -1 | awk '{printf "%s\n",$2}' | sed 's|/24||g')
        if [ -z "$IP" ]; then
            error "$(date) - Setup Unbound - No IP on $INTERFACE"
        else
            echo "outgoing-interface: $IP" >> /etc/unbound/outgoing.conf && success "$(date) - Setup Unbound - outgoing-interface: $IP $INTERFACE > /etc/unbound/outgoing.conf" || error "$(date) - Setup Unbound - Failed: outgoing-interface: $IP $INTERFACE > /etc/unbound/outgoing.conf"
        fi
    done
}
###############################################################################################################
# START SERVICES FOR EACH INTERFACE                                                                           #
###############################################################################################################
batch_health_check() {
    readarray -t interfaces < <(cat /tmp/interfaces)
    for INTERFACE in "${interfaces[@]// /}" ; do 
        echo "systemctl restart health_check_$INTERFACE.service" >> /tmp/batch_health_check.sh
    done
}

###############################################################################################################
# GENERATE SYSTEMD SCRIPT FOR EACH DPINGER INTERFACE MONITOR                                                  #
###############################################################################################################
dpinger_systemd() {
    # Stop old service 
    systemctl -q stop health_check_"$i".service || true && success "$(date) - Stopped health_check_$i.service - Ok" 

cat > /etc/systemd/system/health_check_"$i".service <<EOF && success "$(date) - dpinger_systemd - Dpinger systemd generated for $i" || error "$(date) - dpinger_systemd - Failed to generate Dpinger systemd config for $i"
[Unit]
Description=Health check $i
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/bin/sleep 15
ExecStart=/sbin/dpinger -f -S -i "$i $IP" -R -o "/tmp/health_$i" -L $LOSS -B $IP 1.1.1.1 -C "/bin/bash $SCRIPTS/health_check.sh $i"
Restart=always

[Install]
WantedBy=multi-user.target
EOF
# -D $LATENCY

    # Enable and start
    systemctl -q daemon-reload && success "$(date) - daemon-reload - $i" || fatal "$(date) - daemon-reload - $i"
    systemctl -q enable health_check_"$i".service && success "$(date) - enable health_check_$i.service - Ok" || fatal "$(date) - enable health_check_$i.service - Failed"
}

###############################################################################################################
# SETUP DPINGER SYSTEMD                                                                                       #
###############################################################################################################
setup_dpinger(){
    readarray -t interfaces < <(cat /tmp/interfaces)
    for i in "${interfaces[@]// /}" ; do 
        IP=$(ip address show dev "$i" | grep inet | head -1 | awk '{printf "%s\n",$2}' | sed 's|/24||g')
        dpinger_systemd && success "$(date) - setup_dpinger - Interface monitor service for interface: $i created!" || error "$(date) - setup_dpinger - Failed to create interface monitor service for interface: $i"
    done
}

###############################################################################################################
# INIT                                                                                                        #
###############################################################################################################
header "INIT $(date)"
debug_mode
root_check && success "$(date) - INIT - Root check ok"
find /tmp -type f -iname "script_lock" -delete && success "$(date) - Removed lock file" || success "$(date) - No lock file found to remove"

###############################################################################################################
# UPDATE & UPGRADE & DEPENDENCIES                                                                             #
###############################################################################################################
header "Update & upgrade $(date)"
apt update && success "$(date) - update - Updated" || fatal "$(date) - update - Failed to update"
apt full-upgrade -y && success "$(date) - full-upgrade - Upgraded" || fatal "$(date) - full-upgrade - Failed to upgrade"
header "Dependencies $(date)"
apt install -y unbound dnsutils curl redis-server make clang git && success "$(date) - Dependancies - Installed" || fatal "$(date) - Dependancies - Failed to install"

###############################################################################################################
# GET ALL VALID LTE INTERFACES                                                                                #
###############################################################################################################
header "$(date) - Get all interfaces"
cat /dev/null > /tmp/interfaces && success "$(date) - Get all interfaces - Cleared temp file" || fatal "$(date) - Get all interfaces - Failed to clear temp file"
get_interfaces

###############################################################################################################
# CREATE DIRECTORIES                                                                                          #
###############################################################################################################
mkdir -p "$SCRIPTS" && success "$(date) - Create DIR - $SCRIPTS"
mkdir -p "$SCRIPTS"/ResolvConfBackup && success "$(date) - Create DIR - $SCRIPTS/ResolvConfBackup"

###############################################################################################################
# RC.LOCAL                                                                                                    #
###############################################################################################################
header "$(date) - RC.LOCAL"

if [ -f "/etc/rc.local" ]; then
    warning "$(date) - RC.LOCAL - Exists, backing up to: /etc/backup.rc.local.$DATE"
    cp /etc/rc.local /etc/backup.rc.local."$DATE"
fi

cat > /etc/systemd/system/rc-local.service <<EOF && success "$(date) - Setup RC.LOCAL - Wrote systemd file" || fatal "$(date) - Setup RC.LOCAL - Failed to write systemd file"
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/rc.local <<EOF && success "$(date) - Setup RC.LOCAL - Wrote file" || fatal "$(date) - Setup RC.LOCAL - Failed to write file"
#!/bin/sh -e
# This script is executed at the end of each multiuser runlevel.
# Make sure that the script will "exit 0" on success or any other
# value on error.

# Unbound flush and query checks for evaluation
if [ -f $SCRIPTS/unbound_check.sh]; then
    /bin/bash $SCRIPTS/unbound_check.sh &
fi

# Populate unbound outgoing interfaces
if [ -f $SCRIPTS/set_outgoing_interfaces_onstart.sh]; then
    /bin/bash $SCRIPTS/set_outgoing_interfaces_onstart.sh &
fi

# Redis
echo never > /sys/kernel/mm/transparent_hugepage/enabled

exit 0
EOF

chmod +x /etc/rc.local && success "$(date) - Setup RC.LOCAL - Permissions" || fatal "$(date) - Setup RC.LOCAL - Failed to set permissions"
systemctl enable rc-local && success "$(date) - Setup RC.LOCAL - Enabled service" || fatal "$(date) - Setup RC.LOCAL - Failed to enable service"
systemctl start rc-local && success "$(date) - Setup RC.LOCAL - Start service" || fatal "$(date) - Setup RC.LOCAL - Failed to start service"

###############################################################################################################
# GRAB HEALTH_CHECK.SH                                                                                        #
###############################################################################################################
if ! [ -f "$SCRIPTS"/health_check.sh ]; then
    curl https://raw.githubusercontent.com/WaaromZoMoeilijk/TSP-DNS-fix/main/health_check.sh > "$SCRIPTS"/health_check.sh && success "$(date) - Grab health_check.sh" || error "$(date) - Grab health_check.sh"
    chmod +x "$SCRIPTS"/health_check.sh && success "$(date) - chmod +x health_check.sh" || error "$(date) - chmod +x health_check.sh"
fi

###############################################################################################################
# GRAB SET_OUTGOING_INTERFACES_ONSTART.SH                                                                     #
###############################################################################################################
if ! [ -f "$SCRIPTS"/set_outgoing_interfaces_onstart.sh ]; then
    curl https://raw.githubusercontent.com/WaaromZoMoeilijk/TSP-DNS-fix/main/set_outgoing_interfaces_onstart.sh > "$SCRIPTS"/set_outgoing_interfaces_onstart.sh && success "$(date) - Grab set_outgoing_interfaces_onstart.sh" || error "$(date) - Grab set_outgoing_interfaces_onstart.sh"
    chmod +x "$SCRIPTS"/set_outgoing_interfaces_onstart.sh && success "$(date) - chmod +x set_outgoing_interfaces_onstart.sh - Done" || error "$(date) - chmod +x set_outgoing_interfaces_onstart.sh - Failed"
    sed -i "s|MAINETHNIC=|MAINETHNIC=$MAINETHNIC|g" "$SCRIPTS"/set_outgoing_interfaces_onstart.sh
fi 

###############################################################################################################
# GRAB UNBOUND_CHECK.SH                                                                                       #
###############################################################################################################
if ! [ -f "$SCRIPTS"/unbound_check.sh ]; then
    curl https://raw.githubusercontent.com/WaaromZoMoeilijk/TSP-DNS-fix/main/unbound_check.sh > "$SCRIPTS"/unbound_check.sh && success "$(date) - Grab unbound_check.sh" || error "$(date) - Grab unbound_check.sh"
    chmod +x "$SCRIPTS"/unbound_check.sh && success "$(date) - chmod +x unbound_check.sh" || error "$(date) - chmod +x unbound_check.sh"
fi 

###############################################################################################################
# INSTALL DPINGER                                                                                             #
###############################################################################################################
header "Install Dpinger $(date)"
if ! [ -f /sbin/dpinger ]; then 
    if [ -d /opt/dpinger ]; then
        rm -rf /opt/dpinger && success "$(date) - Install Dpinger - Removed existing /opt/dpinger" || error "$(date) - Install Dpinger - Failed to remove /opt/dpinger"
    fi

    git clone https://gitlab.com/pfsense/dpinger.git /opt/dpinger && success "$(date) - Install Dpinger - Cloned Dpinger with git" || fatal "$(date) - Install Dpinger - Failed to clone Dpinger with git"
    cd /opt/dpinger && success "$(date) - Install Dpinger - Changed directory: /opt/dpinger" || fatal "$(date) - Install Dpinger - Failed to change directory to /opt/dpinger"
    make && success "$(date) - Install Dpinger - MAKE" || fatal "$(date) - Install Dpinger - Failed to MAKE"
    mv dpinger /sbin/dpinger && success "$(date) - Install Dpinger - Moved Dpinger to /sbin" || fatal "$(date) - Install Dpinger - Failed to move Dpinger to /sbin"
    chmod +x /sbin/dpinger && success "$(date) - Install Dpinger - Set permissions on /sbin/dpinger" || fatal "$(date) - Install Dpinger - Failed to set permissions on /sbin/dpinger"
    cd - 
    rm -r /opt/dpinger && success "$(date) - Install Dpinger - Removed leftovers" || fatal "$(date) - Install Dpinger - Failed to remove leftovers"

    if /sbin/dpinger -S -i dpinger -L "$LOSS" -B "$MAINIP" 1.1.1.1; then
        success "$(date) - Install Dpinger - Installed"
        pkill dpinger || true && success "$(date) - Install Dpinger - Test service stopped"
    else
        fatal "$(date) - Install Dpinger - Failed to install"
    fi
fi

###############################################################################################################
# FIX: dhcpcd: script_runreason: control_queue: No buffer space available                                     #
###############################################################################################################
if [ -f /proc/sys/net/core/wmem_max ]; then
    cp /proc/sys/net/core/wmem_max /proc/sys/net/core/wmem_max.backup."$DATE" && success "$(date) - Increase buffer space - Backup wmem_max" || warning "$(date) - Increase buffer space - wmem_max not present for backup"
    echo "638976" > /proc/sys/net/core/wmem_max && success "$(date) - Increase buffer space - wmem_max set to 638976" || warning "$(date) - Increase buffer space - Failed to set wmem_max"
else
    warning "$(date) - Increase buffer space - wmem_max not present"
fi

###############################################################################################################
# DISABLE RESOLVED                                                                                            #
###############################################################################################################
if [ -f etc/systemd/resolved.conf ]; then
    # Disable listening of resolved on port 53 and set dns server to unbound and have cloudflare as fallback IP in case unbound is unreachable
    cp /etc/systemd/resolved.conf /etc/systemd/resolved.backup."$DATE" && success "$(date) - Resolved - Config backed up" || error "$(date) - Resolved - Failed to backup config"

    # The DNSStubListener directive is essential to ensure it does not listen for DNS queries.
    # You may actually want MulticastDNS if you do not use avahi-daemon for multicast-DNS purpose
cat > /etc/systemd/resolved.conf <<EOF && success "$(date) - Resolved - New config set" || fatal "$(date) - Resolved - Failed to set new config"
[Resolve]
DNS=127.0.0.1
FallbackDNS=1.0.0.1 1.1.1.1 8.8.8.8 8.8.4.4
MulticastDNS=no
DNSStubListener=no
EOF

    # systemctl restart systemd-resolved.service && success "$(date) - Resolved - Restarted service" || fatal "$(date) - Resolved - Failed to restart service"
    systemctl stop systemd-resolved.service && success "$(date) - Resolved - Stopped service" || fatal "$(date) - Resolved - Failed to stop service"
    systemctl disable systemd-resolved.service && success "$(date) - Resolved - Disabled service" || fatal "$(date) - Resolved - Failed to disable service"
fi

###############################################################################################################
# RESOLVCONF.CONF                                                                                             #
###############################################################################################################
# Check if file is write protected from previous setups
if ! [ -w "/etc/resolv.conf" ]; then
    chattr -i /etc/resolv.conf && success "$(date) - Setup Unbound - Write protect disabled on /etc/resolv.conf" || fatal "$(date) - Setup Unbound - Failed to disable write protect on /etc/resolv.conf"
fi

# Write config
cat > /etc/resolvconf.conf <<EOF && success "$(date) - Resolveconf.conf - New config set" || fatal "$(date) - Resolveconf.conf - Failed to set new config"
# Configuration for resolvconf(8)
# See resolvconf.conf(5) for details

resolv_conf=/etc/resolv.conf
name_servers=127.0.0.1
EOF

# Reload config
resolvconf -u

# Write protect /etc/resolv.conf
chattr +i /etc/resolv.conf && success "$(date) - Setup Unbound - Write protect set on /etc/resolv.conf" || fatal "$(date) - Setup Unbound - Failed to set write protect on /etc/resolv.conf"

###############################################################################################################
# CLEAR RESOLVCONF HOOK SCRIPTS                                                                               #
###############################################################################################################
# Remove hook file since it overrides /etc/resolv.conf with rubbish
if [ -f /etc/dhcp/dhclient-enter-hooks.d/resolvconf  ]; then
    mv /etc/dhcp/dhclient-enter-hooks.d/resolvconf "$SCRIPTS"/ResolvConfBackup/resolvconf && success "$(date) - Resolvconf - Removed dhcp resolvconf hook" || warning "$(date) - Resolvconf - Failed to remove dhcp resolvconf hook"
fi

if [ -f /lib/dhcpcd/dhcpcd-hooks/20-resolv.conf ]; then
    mv /lib/dhcpcd/dhcpcd-hooks/20-resolv.conf "$SCRIPTS"/ResolvConfBackup/20-resolv.conf && success "$(date) - Resolvconf - Removed dhcpcd resolvconf hook" || warning "$(date) - Resolvconf - Failed to remove dhcpcd resolvconf hook"
fi

###############################################################################################################
# REDIS PERSISTENT DNS CACHE                                                                                  #
###############################################################################################################
if ! crontab -l | grep "transparent_hugepage"; then
    crontab -l | { cat; echo '@reboot /bin/echo never > /sys/kernel/mm/transparent_hugepage/enabled'; } | crontab - && success "$(date) - Redis - Set crontab never > /sys/kernel/mm/transparent_hugepage/enabled" || fatal "$(date) - Redis- Failed to set cronjob never > /sys/kernel/mm/transparent_hugepage/enabled"
    /bin/echo never > /sys/kernel/mm/transparent_hugepage/enabled
fi

systemctl restart redis-server.service && success "$(date) - Setup Redis - Restarted server service" || error "$(date) - Setup  Redis - Failed to restart server service"
systemctl restart redis.service && success "$(date) - Setup Redis - Restarted service" || error "$(date) - Setup  Redis - Failed to restart service"

###############################################################################################################
# SET net.core.rmem_max                                                                                       #
###############################################################################################################
if grep 'net.core.rmem_max' /etc/sysctl.conf; then
	sed -i '/net.core.rmem_max/d' /etc/sysctl.conf && success "$(date) - RMEM MAX - Removed old value from sysctl.conf" || fatal "$(date) - RMEM MAX - Failed to remove old value from sysctl.conf"
fi

echo "net.core.rmem_max=1048576" >> /etc/sysctl.conf 
if sysctl -p | grep 'net.core.rmem_max = 1048576'; then
	success "$(date) - Setup Unbound - Increased net.core.rmem_max"
else
	fatal "$(date) - Setup Unbound - Failed to increase net.core.rmem_max"
fi

###############################################################################################################
# UNBOUND ROOT HINTS CRONJOB                                                                                  #
###############################################################################################################
if ! crontab -l | grep "root.hints"; then
    crontab -l | { cat; echo '0 6 * * * /usr/bin/curl -o "/etc/unbound/root.hints" "https://www.internic.net/domain/named.cache"'; } | crontab - && success "$(date) - Setup Unbound - Cron unbound root.hints" || fatal "$(date) - Setup Unbound - Failed to cron unbound root.hints"
fi

/usr/bin/curl -o "/etc/unbound/root.hints" "https://www.internic.net/domain/named.cache" && success "$(date) - Setup Unbound - Wrote unbound root.hints" || fatal "$(date) - Setup Unbound - Failed to write unbound root.hints"

###############################################################################################################
# UNBOUND                                                                                                     #
###############################################################################################################
cat > /etc/unbound/unbound.conf <<EOF && success "$(date) - Setup Unbound - Wrote unbound config" || fatal "$(date) - Setup Unbound - Failed to write unbound config"
###########################################################################
# Redis cache
###########################################################################
cachedb:
    backend: "redis"
    redis-server-host: 127.0.0.1
    redis-server-port: 6379
    redis-timeout: 60

server:
###########################################################################
# BASIC SETTINGS
###########################################################################
    # domain-insecure: "tlvproxy.thesocialproxy.com"
    # private-domain: 

    # Time to live maximum for RRsets and messages in the cache. If the maximum
    # kicks in, responses to clients still get decrementing TTLs based on the
    # original (larger) values. When the internal TTL expires, the cache item
    # has expired. Can be set lower to force the resolver to query for data
    # often, and not trust (very large) TTL values.
    cache-max-ttl: 86400

    # Time to live minimum for RRsets and messages in the cache. If the minimum
    # kicks in, the data is cached for longer than the domain owner intended,
    # and thus less queries are made to look up the data. Zero makes sure the
    # data in the cache is as the domain owner intended, higher values,
    # especially more than an hour or so, can lead to trouble as the data in
    # the cache does not match up with the actual data any more.
    cache-min-ttl: 600

    # Set the working directory for the program.
    # directory: "/etc/unbound"

    # RFC 6891. Number of bytes size to advertise as the EDNS reassembly buffer
    # size. This is the value put into datagrams over UDP towards peers.
    # 4096 is RFC recommended. 1472 has a reasonable chance to fit within a
    # single Ethernet frame, thus lessing the chance of fragmentation
    # reassembly problems (usually seen as timeouts). Setting to 512 bypasses
    # even the most stringent path MTU problems, but is not recommended since
    # the amount of TCP fallback generated is excessive.
    edns-buffer-size: 1472

    # Listen for queries from clients and answer from this network interface
    # and port.
    interface: 0.0.0.0@53

    # Rotates RRSet order in response (the pseudo-random number is taken from
    # the query ID, for speed and thread safety).
    rrset-roundrobin: yes

    # Drop user  privileges after binding the port.
    username: "unbound"

    # Include outgoing interfaces
    include: "/etc/unbound/outgoing.conf"

    #  stops the resolver from withholding bogus answers from clients. Resolution may be slow due to validation failures but can still proceed
    val-permissive-mode: yes
    
    # Turn off validator module for DNSSEC
    module-config: "iterator"

    infra-cache-min-rtt: 500
    infra-cache-numhosts: 100000

    do-ip4: yes
    do-udp: yes
    do-tcp: yes

    # May be set to yes if you have IPv6 connectivity
    do-ip6: no

    # You want to leave this to no unless you have *native* IPv6. With 6to4 and
    # Terredo tunnels your web browser should favor IPv4 for the same reasons
    prefer-ip6: no

    ###########################################################################
    # LOGGING
    ###########################################################################

    # Do not print log lines to inform about local zone actions
    log-local-actions: no

    # Do not print one line per query to the log
    log-queries: no

    # Do not print one line per reply to the log
    log-replies: no

    # Do not print log lines that say why queries return SERVFAIL to clients
    log-servfail: no

    # Further limit logging
    # logfile: /dev/null

    # Only log errors
    verbosity: 2
    use-syslog: yes

    # Use this only when you downloaded the list of primary root servers!
    root-hints: "root.hints"

    ###########################################################################
    # PRIVACY SETTINGS
    ###########################################################################

    # RFC 8198. Use the DNSSEC NSEC chain to synthesize NXDO-MAIN and other
    # denials, using information from previous NXDO-MAINs answers. In other
    # words, use cached NSEC records to generate negative answers within a
    # range and positive answers from wildcards. This increases performance,
    # decreases latency and resource utilization on both authoritative and
    # recursive servers, and increases privacy. Also, it may help increase
    # resilience to certain DoS attacks in some circumstances.
    # aggressive-nsec: yes

    # Extra delay for timeouted UDP ports before they are closed, in msec.
    # This prevents very delayed answer packets from the upstream (recursive)
    # servers from bouncing against closed ports and setting off all sort of
    # close-port counters, with eg. 1500 msec. When timeouts happen you need
    # extra sockets, it checks the ID and remote IP of packets, and unwanted
    # packets are added to the unwanted packet counter.
    delay-close: 10000

    # Prevent the unbound server from forking into the background as a daemon
    # do-daemonize: no

    # Add localhost to the do-not-query-address list.
    do-not-query-localhost: no

    # Number  of  bytes size of the aggressive negative cache.
    neg-cache-size: 4M

    # Send minimum amount of information to upstream servers to enhance
    # privacy (best privacy).
    qname-minimisation: yes

    ###########################################################################
    # SECURITY SETTINGS
    ###########################################################################
    # Only give access to recursion clients from LAN IPs
    access-control: 127.0.0.1/32 allow
    access-control: 192.168.0.0/16 allow
    access-control: 172.16.0.0/12 allow
    access-control: 10.0.0.0/8 allow
    access-control: fc00::/7 allow
    access-control: ::1/128 allow

    # File with trust anchor for  one  zone, which is tracked with RFC5011
    # probes.
    # auto-trust-anchor-file: "var/root.key"

    # Enable chroot (i.e, change apparent root directory for the current
    # running process and its children)
    # chroot: "/etc/unbound"
    
    # Deny queries of type ANY with an empty response.
    deny-any: yes

    # Harden against algorithm downgrade when multiple algorithms are
    # advertised in the DS record.
    harden-algo-downgrade: yes

    # RFC 8020. returns nxdomain to queries for a name below another name that
    # is already known to be nxdomain.
    harden-below-nxdomain: yes

    # Require DNSSEC data for trust-anchored zones, if such data is absent, the
    # zone becomes bogus. If turned off you run the risk of a downgrade attack
    # that disables security for a zone.
    harden-dnssec-stripped: yes

    # Only trust glue if it is within the servers authority.
    harden-glue: yes

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

    # These private network addresses are not allowed to be returned for public
    # internet names. Any  occurrence of such addresses are removed from DNS
    # answers. Additionally, the DNSSEC validator may mark the  answers  bogus.
    # This  protects  against DNS  Rebinding
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: fd00::/8
    private-address: fe80::/10
    private-address: ::ffff:0:0/96

    # Enable ratelimiting of queries (per second) sent to nameserver for
    # performing recursion. More queries are turned away with an error
    # (servfail). This stops recursive floods (e.g., random query names), but
    # not spoofed reflection floods. Cached responses are not rate limited by
    # this setting. Experimental option.
    ratelimit: 1000

    # Use this certificate bundle for authenticating connections made to
    # outside peers (e.g., auth-zone urls, DNS over TLS connections).
    tls-cert-bundle: /etc/ssl/certs/ca-certificates.crt

    # Set the total number of unwanted replies to keep track of in every thread.
    # When it reaches the threshold, a defensive action of clearing the rrset
    # and message caches is taken, hopefully flushing away any poison.
    # Unbound suggests a value of 10 million.
    unwanted-reply-threshold: 500000

    # Use 0x20-encoded random bits in the query to foil spoof attempts. This
    # perturbs the lowercase and uppercase of query names sent to authority
    # servers and checks if the reply still has the correct casing.
    # This feature is an experimental implementation of draft dns-0x20.
    # Experimental option.
    # use-caps-for-id: yes

    # Help protect users that rely on this validator for authentication from
    # potentially bad data in the additional section. Instruct the validator to
    # remove data from the additional section of secure messages that are not
    # signed properly. Messages that are insecure, bogus, indeterminate or
    # unchecked are not affected.
    # val-clean-additional: yes

    ###########################################################################
    # PERFORMANCE SETTINGS
    ###########################################################################
    # https://nlnetlabs.nl/documentation/unbound/howto-optimise/

    # Number of slabs in the infrastructure cache. Slabs reduce lock contention
    # by threads. Must be set to a power of 2.
    infra-cache-slabs: 2

    # Number of slabs in the key cache. Slabs reduce lock contention by
    # threads. Must be set to a power of 2. Setting (close) to the number
    # of cpus is a reasonable guess.
    key-cache-slabs: 2

    # Number  of  bytes  size  of  the  message  cache.
    # Unbound recommendation is to Use roughly twice as much rrset cache memory
    # as you use msg cache memory.
    msg-cache-size: 128525653

    # Number of slabs in the message cache. Slabs reduce lock contention by
    # threads. Must be set to a power of 2. Setting (close) to the number of
    # cpus is a reasonable guess.
    msg-cache-slabs: 2

    # The number of queries that every thread will service simultaneously. If
    # more queries arrive that need servicing, and no queries can be jostled
    # out (see jostle-timeout), then the queries are dropped.
    # This is best set at half the number of the outgoing-range.
    # This Unbound instance was compiled with libevent so it can efficiently
    # use more than 1024 file descriptors.
    num-queries-per-thread: 4096

    # The number of threads to create to serve clients.
    # This is set dynamically at run time to effectively use available CPUs
    # resources
    num-threads: 2

    # Number of ports to open. This number of file descriptors can be opened
    # per thread.
    # This Unbound instance was compiled with libevent so it can efficiently
    # use more than 1024 file descriptors.
    outgoing-range: 8192

    # Number of bytes size of the RRset cache.
    # Use roughly twice as much rrset cache memory as msg cache memory
    rrset-cache-size: 257051306

    # Number of slabs in the RRset cache. Slabs reduce lock contention by
    # threads. Must be set to a power of 2.
    rrset-cache-slabs: 4

    # Do no insert authority/additional sections into response messages when
    # those sections are not required. This reduces response size
    # significantly, and may avoid TCP fallback for some responses. This may
    # cause a slight speedup.
    minimal-responses: yes

    # # Fetch the DNSKEYs earlier in the validation process, when a DS record
    # is encountered. This lowers the latency of requests at the expense of
    # little more CPU usage.
    prefetch: yes

    # Fetch the DNSKEYs earlier in the validation process, when a DS record is
    # encountered. This lowers the latency of requests at the expense of little
    # more CPU usage.
    prefetch-key: yes

    # Have unbound attempt to serve old responses from cache with a TTL of 0 in
    # the response without waiting for the actual resolution to finish. The
    # actual resolution answer ends up in the cache later on.
    serve-expired: yes
    serve-expired-ttl: 0
    serve-expired-ttl-reset: yes

    # Open dedicated listening sockets for incoming queries for each thread and
    # try to set the SO_REUSEPORT socket option on each socket. May distribute
    # incoming queries to threads more evenly.
    so-reuseport: yes

    ###########################################################################
    # LOCAL ZONE
    ###########################################################################

    # Include file for local-data and local-data-ptr
    # include: /etc/unbound/a-records.conf

    ###########################################################################
    # FORWARD ZONE
    ###########################################################################
    forward-zone:
        # Forward all queries (except those in cache and local zone) to
        # upstream recursive servers
        name: "."
        # Queries to this forward zone use TLS
        forward-tls-upstream: yes

        # https://dnsprivacy.org/wiki/display/DP/DNS+Privacy+Test+Servers

        # Cloudflare
        forward-addr: 1.1.1.1@853#cloudflare-dns.com
        forward-addr: 1.0.0.1@853#cloudflare-dns.com
        #forward-addr: 2606:4700:4700::1111@853#cloudflare-dns.com
        #forward-addr: 2606:4700:4700::1001@853#cloudflare-dns.com

        # Quad9
        forward-addr: 9.9.9.9@853#dns.quad9.net
        forward-addr: 149.112.112.112@853#dns.quad9.net
        # forward-addr: 2620:fe::fe@853#dns.quad9.net
        # forward-addr: 2620:fe::9@853#dns.quad9.net

        # Google
        forward-addr: 8.8.8.8@853#dns.google
        forward-addr: 8.8.4.4@853#dns.google
        #forward-addr: 2001:4860:4860::8888 @853#dns.google
        #forward-addr: 2001:4860:4860::8844@853#dns.google

        # getdnsapi.net
        forward-addr: 185.49.141.37@853#getdnsapi.net
        #forward-addr: 2a04:b900:0:100::37@853#getdnsapi.net

        # Surfnet
        forward-addr: 145.100.185.15@853#dnsovertls.sinodun.com
        forward-addr: 145.100.185.16@853#dnsovertls1.sinodun.com
        forward-addr: 145.100.185.17@853#dnsovertls2.sinodun.com
        forward-addr: 145.100.185.18@853#dnsovertls3.sinodun.com
	    #forward-addr: 2001:610:1:40ba:145:100:185:15@853#dnsovertls.sinodun.com
        #forward-addr: 2001:610:1:40ba:145:100:185:16@853#dnsovertls1.sinodun.com

remote-control:
    control-enable: yes
EOF

# Add all available NICs as outbound interface for unbound
if [ -f /etc/unbound/outgoing.conf ]; then
    rm -rf /etc/unbound/outgoing.conf 
fi

# Remove outgoing.conf backup
if [ -f "$SCRIPTS"/outgoing.conf ]; then
    rm -rf "$SCRIPTS"/outgoing.conf
fi

set_outgoing_interfaces_unbound

systemctl enable unbound.service && success "$(date) - Setup Unbound - Enabled service" || fatal "$(date) - Setup Unbound - Failed to enable service"
systemctl restart unbound.service && success "$(date) - Setup Unbound - Restarted service" || fatal "$(date) - Setup Unbound - Failed to restart service"

###############################################################################################################
# TEST UNBOUND                                                                                                #
###############################################################################################################
sleep 5
unbound-control flush facebook.com && success "$(date) - DNS Check - Flush DNS" || fatal "$(date) - DNS Check - Flushing DNS failed"

if host facebook.com; then
    success "$(date) - DNS Check - DNS is working via unbound!"
else
    warning "$(date) - DNS Check - DNS is not working via unbound! Please test after the script is done and you're rebooted, with: host facebook.com"
fi

###############################################################################################################
# SETUP DPINGER                                                                                               #
###############################################################################################################
header "$(date) - Dpinger systemd generator"

# Create services for the health check of each interface inside /etc/systemd/systemd/health_check_$interface.service
setup_dpinger

# Starting each service with the ExecStart delay takes ages when there are 80+ interfaces.
# Lets them in the background or just simply reboot after installation
if [ -f /tmp/batch_health_check.sh ]; then
    rm /tmp/batch_health_check.sh
fi

sleep 5
batch_health_check
bash /tmp/batch_health_check.sh & success "$(date) - start batch health_check.service - Ok" || fatal "$(date) - start batch health_check.service - Failed"  

###############################################################################################################
# APT FORCE IPV4                                                                                              #
###############################################################################################################
header "$(date) - APT Force IPV4"
if [ "$APTIPV4" == "ON" ]; then
    echo 'Acquire::ForceIPv4 “true”;' > /etc/apt/apt.conf.d/99force-ipv4 && success "$(date) - Misc - Force APT to use IPV4" || fatal "$(date) - Misc - Failed to force APT to use IPV4"
fi

###############################################################################################################
# MISC                                                                                                        #
###############################################################################################################
header "$(date) - Misc"

###############################################################################################################
# END                                                                                                         #
###############################################################################################################
success "$(date) - Script finished - $COUNTER Warning(s) and / or error(s)"
cat /var/log/health_check_script_errors_warnings.log | grep -v 'Loss is still higher' | grep -v 'Failed to reload unbound'

exit 0
