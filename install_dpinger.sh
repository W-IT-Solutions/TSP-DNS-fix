#!/bin/bash 
# shellcheck disable=
# Jan 6 2022 - scripting@waaromzomoeilijk.nl
#
# This is a leftover from dpinger testing to fix the interfaces not being managed by their performance/state
# For reference

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

################################ Dynamic systemd script generator for dpinger interface monitor
dpinger_systemd() {
cat > /etc/systemd/system/health_check_"$i".service <<EOF && success "$(date) - dpinger_systemd - Dpinger systemd generated for $i" || error "$(date) - dpinger_systemd - Failed to generate Dpinger systemd config for $i"
[Unit]
Description=Health check $i
After=network.target

[Service]
Type=simple
ExecStart=/sbin/dpinger -f -L $LOSS -B $IP 1.1.1.1 -C "/bin/bash /var/scripts/health_check.sh $i"
Restart=on-failure
StartLimitBurst=2
# Restart, but not more than once every 10 minutes
StartLimitInterval=600
#StartLimitInterval=30

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
systemctl -q stop health_check_"$i".service || true && success "$(date) - Stopped health_check_$i.service - Ok" 
systemctl -q daemon-reload && success "$(date) - daemon-reload - $i" || fatal "$(date) - daemon-reload - $i"
systemctl -q enable health_check_"$i".service && success "$(date) - enable health_check_$i.service - Ok" || fatal "$(date) - enable health_check_$i.service - Failed"
systemctl -q start health_check_"$i".service && success "$(date) - start health_check_$i.service - Ok" || fatal "$(date) - start health_check_$i.service - Failed"  
}

################################ Execute systemd script generator for dpinger interface monitor with proper variable's
setup_dpinger(){
    readarray -t interfaces < <(cat /tmp/interfaces)
    for i in "${interfaces[@]// /}" ; do 
        IP=$(ip address show dev "$i" | grep inet | head -1 | awk '{printf "%s\n",$2}' | sed 's|/24||g')
        dpinger_systemd && success "$(date) - setup_dpinger - Interface monitor service for interface: $i created!" || error "$(date) - setup_dpinger - Failed to create interface monitor service for interface: $i"
    done
}

################################ Pre init
header "Pre init $(date)"
debug_mode
root_check && success "$(date) - INIT - Root check ok"
#health_check_script && success "$(date) - INIT - Health check script created!" || fatal "$(date) - INIT - Failed to create health check script"

################################ Update and upgrade
header "Update & upgrade $(date)"
apt update && success "$(date) - update - Updated" || fatal "$(date) - update - Failed to update"
apt full-upgrade -y && success "$(date) - full-upgrade - Upgraded" || fatal "$(date) - full-upgrade - Failed to upgrade"
header "Dependencies $(date)"
apt install -y make clang git && success "$(date) - Dependancies - Installed" || fatal "$(date) - Dependancies - Failed to install"

################################ Install Dpinger, lightweight interface health monitor
header "Install Dpinger $(date)"

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

################################ Get all valid interfaces to setup for dpinger monitoring 
header "$(date) - Get all interfaces"
cat /dev/null > /tmp/interfaces && success "$(date) - Get all interfaces - Cleared temp file" || fatal "$(date) - Get all interfaces - Failed to clear temp file"
get_interfaces

################################ Create scripts and dpinger dir
mkdir -p /var/scripts && success "$(date) - Create DIRs - Scripts dir created"
mkdir -p /var/scripts/interfaces && success "$(date) - Create DIRs - Scripts/Interfaces dir created"

################################ Create services for the health check of each interface inside /var/scripts/dpinger/$interface.sh
header "$(date) - Dpinger systemd generator"
setup_dpinger

################################  Misc
header "$(date) - Misc"

# End of script
success "$(date) - Script finished - $COUNTER Warning(s) and / or error(s)"
cat /var/log/health_check_script_errors_warnings.log

exit 0
