#!/bin/bash 
# shellcheck disable=SC2034,SC2015,SC2116
# Jan 6 2022 - scripting@waaromzomoeilijk.nl
# Install unbound as local dns cache server, let the system use that as its primary DNS and let unbound query DNS requests over all LTE interfaces
# This uses https://www.cloudflare.com/learning/dns/dns-over-tls/ (optional)
#
# Unbound needs to build up a cache of results before it starts to speed up.
# When you browse websites you make dozens of DNS queries for different resources (JavaScript, CSS, etc). 
# Lots of these libraries are commonly used across multiple websites.
# Unbound will soon learn where those resources are and won't have to do a full lookup every time.
#
# Final speed tweaks will be added soon and this message will be removed.
#
# i can also make it so that unbound will only use working interfaces - verified works! just have to automate it
#
# Create test script dig
# load_cache & dump_cache
#
# 


something is settings different DNS servers in /etc/resolv.conf
add cache dump every 15 minutes
add cache load @reboot

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
SYSCTL=$(grep 'net.core.rmem_max' /etc/sysctl.conf)

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
get_interfaces() {
    readarray -t interfaces < <(ip l | grep enp | grep -v "$MAINETHNIC" |  awk '{printf "%s\n",$2}' | sed 's/://g' | sed -r '/^\s*$/d' | cut -f1 -d"@")
    for i in "${interfaces[@]// /}" ; do 
        echo "$i" >> /tmp/interfaces && success "$(date) - get_interfaces - Found interface: $i"
    done
}

################################ Hardcode outgoing interfaces in unbound config
set_outgoing_interfaces_unbound() {
    readarray -t interfaces < <(cat /tmp/interfaces)
    for INTERFACE in "${interfaces[@]// /}" ; do 
        IP=$(ip address show dev "$INTERFACE" | grep inet | head -1 | awk '{printf "%s\n",$2}' | sed 's|/24||g')
        if [ -z "$IP" ]; then
            error "$(date) - Setup Unbound - No IP on $INTERFACE"
        else
            echo "outgoing-interface: $IP" >> /etc/unbound/outgoing.conf
            echo "nameserver $IP" >> /etc/resolv.conf
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
apt install -y unbound dnsutils curl redis-server && success "$(date) - Dependancies - Installed" || fatal "$(date) - Dependancies - Failed to install"

################################ Get all valid LTE interfaces
header "$(date) - Get all interfaces"
cat /dev/null > /tmp/interfaces && success "$(date) - Get all interfaces - Cleared temp file" || fatal "$(date) - Get all interfaces - Failed to clear temp file"
get_interfaces

################################ Create scripts dir
mkdir -p /var/scripts && success "$(date) - Create DIRs - Scripts dir created"
mkdir -p /var/scripts/ResolvConfBackup && success "$(date) - Create DIRs - Scripts/ResolvConfBackup dir created"

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
FallbackDNS=1.0.0.1 1.1.1.1 8.8.8.8 8.8.4.4
MulticastDNS=no
DNSStubListener=no
EOF

# systemctl restart systemd-resolved.service && success "$(date) - Resolved - Restarted service" || fatal "$(date) - Resolved - Failed to restart service"
systemctl stop systemd-resolved.service && success "$(date) - Resolved - Stopped service" || fatal "$(date) - Resolved - Failed to stop service"
systemctl disable systemd-resolved.service && success "$(date) - Resolved - Disabled service" || fatal "$(date) - Resolved - Failed to disable service"

################################  Dhcpcd.conf
#sed -i '/static routers=192.168.8.1/a static domain_name_servers=127.0.0.1' /etc/dhcpcd.conf
#sed -i '/static domain_name_servers=127.0.0.1/a \ ' /etc/dhcpcd.conf

################################ Setup Redis cache for unbound DNS entries
cat > /etc/redis/redis.conf <<EOF && success "$(date) - Setup Unbound - Wrote redis config" || fatal "$(date) - Setup Unbound - Failed to write redis config"
# Redis configuration file example.
#
# Note that in order to read the configuration file, Redis must be
# started with the file path as first argument:
#
# ./redis-server /path/to/redis.conf

# TCP listen() backlog.
#
# In high requests-per-second environments you need an high backlog in order
# to avoid slow clients connections issues. Note that the Linux kernel
# will silently truncate it to the value of /proc/sys/net/core/somaxconn so
# make sure to raise both the value of somaxconn and tcp_max_syn_backlog
# in order to get the desired effect.
tcp-backlog 511

bind 127.0.0.1
protected-mode yes
port 6379
# unixsocket /var/run/redis/redis-server.sock
# unixsocketperm 700
tcp-keepalive 300
supervised no
daemonize yes
rdb-save-incremental-fsync yes
aof-rewrite-incremental-fsync yes
dynamic-hz yes
hz 50
client-output-buffer-limit normal 0 0 0
client-output-buffer-limit replica 256mb 64mb 60
client-output-buffer-limit pubsub 32mb 8mb 60
activerehashing yes
stream-node-max-bytes 4096
stream-node-max-entries 100
zset-max-ziplist-entries 128
zset-max-ziplist-value 64
hll-sparse-max-bytes 3000
set-max-intset-entries 512
list-compress-depth 0
list-max-ziplist-size -2
hash-max-ziplist-entries 512
hash-max-ziplist-value 64
notify-keyspace-events ""
latency-monitor-threshold 0
slowlog-max-len 128
slowlog-log-slower-than 10000
lua-time-limit 5000
aof-use-rdb-preamble yes
aof-load-truncated yes
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb
no-appendfsync-on-rewrite no
appendfsync everysec
appendfilename "appendonly.aof"
appendonly no
lazyfree-lazy-eviction no
lazyfree-lazy-expire no
lazyfree-lazy-server-del no
replica-lazy-flush no
repl-disable-tcp-nodelay no
repl-diskless-sync no
repl-diskless-sync-delay 5
replica-read-only yes
replica-serve-stale-data yes
dir /var/lib/redis
dbfilename dump.rdb
rdbchecksum yes
rdbcompression yes
stop-writes-on-bgsave-error yes
save 900 1
save 300 10
save 60 10000
databases 16
logfile /var/log/redis/redis-server.log
loglevel notice
EOF

systemctl restart redis-server.service && success "$(date) - Setup Redis - Restarted service" || error "$(date) - Setup  Redis - Failed to restart service"
systemctl restart redis.service && success "$(date) - Setup Redis - Restarted service" || error "$(date) - Setup  Redis - Failed to restart service"

################################ Setup Unbound
# Setup root.hint grab cronjob
if ! crontab -l | grep "root.hints"; then
    # Cronjob check
        crontab -l | { cat; echo '0 6 * * * /usr/bin/curl -o "/etc/unbound/root.hints" "https://www.internic.net/domain/named.cache"'; } | crontab - && success "$(date) - Setup Unbound - Wrote unbound root.hints" || fatal "$(date) - Setup Unbound - Failed to write unbound root.hints"
fi

# Check and increase net.core.rmem_max
if $SYSCTL; then
	sed -i "/net.core.rmem_max/d" /etc/sysctl.conf && success "$(date) - RMEM MAX - Removed old value from sysctl.conf" || fatal "$(date) - RMEM MAX - Failed to remove old value from sysctl.conf"
	echo "#net.core.rmem_max=$SYSCTL # Old value" >> /etc/sysctl.conf && success "$(date) - RMEM MAX - Backed up old value of rmem_max in sysctl.conf" || fatal "$(date) - RMEM MAX - Failed to backup old value of rmem_max in sysctl.conf"
fi

echo "net.core.rmem_max=1048576" >> /etc/sysctl.conf 
if sysctl -p | grep 'net.core.rmem_max=1048576'; then
	success "$(date) - Setup Unbound - Increased net.core.rmem_max"
else
	fatal "$(date) - Setup Unbound - Failed to increase net.core.rmem_max"
fi

# Unbound
cat > /etc/unbound/unbound.conf <<EOF && success "$(date) - Setup Unbound - Wrote unbound config" || fatal "$(date) - Setup Unbound - Failed to write unbound config"
###########################################################################
    ###########################################################################
    # Redis cache
    ###########################################################################
cachedb:
    backend: "redis"
    redis-server-host: 127.0.0.1
    redis-server-port: 6379
    redis-timeout: 100

server:
    ###########################################################################
    # BASIC SETTINGS
    ###########################################################################
    domain-insecure: "tlvproxy.thesocialproxy.com"
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

    # Drop user  privileges after  binding the port.
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
#    aggressive-nsec: yes

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
#
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

    # Set the total number of unwanted replies to eep track of in every thread.
    # When it reaches the threshold, a defensive action of clearing the rrset
    # and message caches is taken, hopefully flushing away any poison.
    # Unbound suggests a value of 10 million.
    unwanted-reply-threshold: 500000

    # Use 0x20-encoded random bits in the query to foil spoof attempts. This
    # perturbs the lowercase and uppercase of query names sent to authority
    # servers and checks if the reply still has the correct casing.
    # This feature is an experimental implementation of draft dns-0x20.
    # Experimental option.
#    use-caps-for-id: yes

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

set_outgoing_interfaces_unbound

systemctl enable unbound.service && success "$(date) - Setup Unbound - Enabled service" || fatal "$(date) - Setup Unbound - Failed to enable service"
systemctl restart unbound.service && success "$(date) - Setup Unbound - Restarted service" || fatal "$(date) - Setup Unbound - Failed to restart service"

################################ Check resolv.conf, needs to be updated by resolved automagically
# Remove this hook file since it overrides /etc/resolv.conf with rubbish
if [ -f /etc/dhcp/dhclient-enter-hooks.d/resolvconf  ]; then
    mv /etc/dhcp/dhclient-enter-hooks.d/resolvconf /var/scripts/ResolvConfBackup/resolvconf && success "$(date) - Resolvconf - Removed dhcp resolvconf hook" || warning "$(date) - Resolvconf - Failed to remove dhcp resolvconf hook"
fi

if [ -f /lib/dhcpcd/dhcpcd-hooks/20-resolv.conf ]; then
    mv /lib/dhcpcd/dhcpcd-hooks/20-resolv.conf /var/scripts/ResolvConfBackup/20-resolv.conf && success "$(date) - Resolvconf - Removed dhcpcd resolvconf hook" || warning "$(date) - Resolvconf - Failed to remove dhcpcd resolvconf hook"
fi

# Just to be safe
#crontab -l | { cat; echo '* * * * * echo "nameserver 127.0.0.1" > /etc/resolv.conf'; } | crontab - && success "$(date) - Resolvconf - Set cronjob: 127.0.0.1 as nameserver in /etc/resolv.conf" || warning "$(date) - Resolvconf - Failed to set cronjob: 127.0.0.1 as nameserver in /etc/resolv.conf"
mv /etc/resolv.conf /etc/resolv.conf.backup."$DATE"
echo "nameserver 127.0.0.1" >> /etc/resolv.conf && success "$(date) - Resolvconf - Set 127.0.0.1 as nameserver in /etc/resolv.conf" || warning "$(date) - Resolvconf - Failed to set 127.0.0.1 as nameserver in /etc/resolv.conf"
# Write protect /etc/resolv.conf
chattr +i /etc/resolv.conf && success "$(date) - Setup Unbound - Write protect set on /etc/resolv.conf" || fatal "$(date) - Setup Unbound - Failed to to set write protect on /etc/resolv.conf"


################################ DNS check loopback -> unbound cache/forward
# Clear current DNS cache
unbound-control flush && success "$(date) - DNS Check - Flush DNS" || fatal "$(date) - DNS Check - Flushing DNS failed"

if host facebook.com; then
    success "$(date) - DNS Check - DNS is working via unbound!"
else
    fatal "$(date) - DNS Check - DNS is not working via unbound!"
fi

################################  Misc
header "$(date) - Misc"

if [ "$APTIPV4" == "ON" ]; then
    echo 'Acquire::ForceIPv4 “true”;' > /etc/apt/apt.conf.d/99force-ipv4 && success "$(date) - Misc - Force APT to use IPV4" || fatal "$(date) - Misc - Failed to force APT to use IPV4"
fi

# End of script
success "$(date) - Script finished - $COUNTER Warning(s) and / or error(s)"
cat /var/log/health_check_script_errors_warnings.log

exit 0
