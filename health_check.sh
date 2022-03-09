#!/bin/bash
# shellcheck disable=SC2015,SC2004,SC2002
# Jan 6 2022 - scripting@waaromzomoeilijk.nl
###############################################################################################################
# LOGGER                                                                                                      #
###############################################################################################################
INTERACTIVE="0" # 1 = on / 0 = off - Log all script output to file (0) or just output everything in stout (1)
if ! [ "$INTERACTIVE" == 1 ]; then 
    LOGFILE="/var/log/health_check.log" # Log file
    exec 3>&1 4>&2
    trap 'exec 2>&4 1>&3' 0 1 2 3 15 RETURN
    exec 1>>"$LOGFILE" 2>&1
fi

###############################################################################################################
# CMD LINE OUTPUT                                                                                             #
###############################################################################################################
print_text_in_color() {
	/usr/bin/printf "%b%s%b\n" "$1" "$2" "$Color_Off"
}
Color_Off='\e[0m'   # Text Reset
IRed='\e[0;91m' 	# Red
IGreen='\e[0;92m'   # Green
IYellow='\e[0;93m'  # Yellow
IBlue='\e[0;94m'	# Blue

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
	if [ -f /tmp/.script_lock_"$1" ]; then
		rm -rf /tmp/.script_lock_"$1" && success "$(date) - $1 - Removed /tmp/.script_lock_$1 prematurely"
	fi
	exit 1
}

###############################################################################################################
# CHECK / SET LOCK                                                                                            #
###############################################################################################################
if [ -f /tmp/.script_lock_"$1" ]; then
    	warning "$(date) - $1 - Script is already running"
	exit 1
else
   	 touch /tmp/.script_lock_"$1" && success "$(date) - $1 - Created /tmp/.script_lock_$1" || fatal "$(date) - $1 - Failed to create /tmp/.script_lock_$1"
fi

###############################################################################################################
# INTERFACE VARIABLE CHECK                                                                                    #
###############################################################################################################
header "$(date) - $1 - Health check initiated"
if [ -n "$1" ]; then
	INTERFACE="$1"
	success "$(date) - $INTERFACE - Interface parameter detected"
else
	fatal "$(date) - Interface parameter not detected"
fi

###############################################################################################################
# VARIABLES                                                                                                   #
###############################################################################################################
DEBUG="0" # 1 = on / 0 = off
IP=$(ip address show dev "$INTERFACE" | grep inet | head -1 | awk '{printf "%s\n",$2}' | sed 's|/24||g')
#GW='192.168.8.1'
#NETWORK='192.168.8' # Leave OUT the last dot and octet 
WAITSEC="10" # Loop time, every 10 seconds
#METRIC=$(route -n | grep 'UG' | grep "$INTERFACE" | awk '{printf "%s\n",$5}')
#octet=$(ip address show dev "$INTERFACE" | grep inet | awk -F "[/.]" '{print $4;}')
#tablenum=$(( $octet + 100 ))
LOSS="15"

# Dpinger vars
dest_addr="$4"
alarm_flag="$5"
latency_avg="$7"
loss_avg="$8"

# Check IP var
if [ -n "$IP" ]; then
	success "$(date) - $INTERFACE - IP variable detected"
else
	fatal "$(date) - $INTERFACE - IP variable not detected"
fi

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
		set -ex && success "$(date) - $INTERFACE $IP - INIT - Debug set" || error "$(date) - $INTERFACE $IP - INIT - Setting debug failed"
	fi
}

###############################################################################################################
# INIT                                                                                                        #
###############################################################################################################
debug_mode
root_check
# Remove when verified
header "$(date) - $INTERFACE $IP - INIT - Use Dpinger variables: dest_addr $dest_addr alarm_flag $alarm_flag latency_avg $latency_avg loss_avg $loss_avg"

###############################################################################################################
# LOOP: CHECK LINK AND ACT                                                                                    #
###############################################################################################################
while :
do
	CONNECTION=$(cat "/tmp/health_$INTERFACE" | awk '{print $5}')
	if ! [ -f /tmp/health_"$INTERFACE" ]; then
		error "$(date) - $INTERFACE - Failed to read /tmp/health_$INTERFACE"
	fi

	if [ "$CONNECTION" == "0" ]; then

		if grep -q "$IP" /etc/unbound/outgoing.conf; then
			warning "$(date) - $INTERFACE $IP - Interface is present in /etc/unbound/outgoing.conf already."
		else
			# Set unbound interfaces and reload
			echo "outgoing-interface: $IP" >> /etc/unbound/outgoing.conf
			#unbound-control dump_cache > /etc/unbound/cache.file && success "$(date) - Backed up unbound cache to /etc/unbound/cache.file" || error "$(date) - Failed to backup unbound cache to /etc/unbound/cache.file"
			#unbound-control reload && success "$(date) - Reload unbound" || error "$(date) - Failed to reload unbound"
			#unbound-control load_cache < /etc/unbound/cache.file && success "$(date) - Loaded unbound cache from /etc/unbound/cache.file" || error "$(date) - Failed to load unbound cache from /etc/unbound/cache.file"
			service unbound restart
		fi

		# If loss is 0% set original metric value back
		##ifmetric "$INTERFACE" "$METRIC" && success "$(date) - $INTERFACE - IFMETRIC set to old value of: $METRIC" || fatal "$(date) - $INTERFACE - Failed to set metric to old value of: $METRIC"

		# Abandon the loop.
		success "$(date) - $INTERFACE $IP - Break the loop"
		break

	elif [ "$CONNECTION" -gt "$LOSS" ]; then
		error "$(date) - $INTERFACE $IP - Still down, loss: $CONNECTION% -gt 15%"

		if grep "$IP" /etc/unbound/outgoing.conf; then
			sed -i "/$IP/d" /etc/unbound/outgoing.conf && success "$(date) - Removed outgoing interface $IP from /etc/unbound/outgoing.conf" || error "$(date) - Failed to removed outgoing interface $IP from /etc/unbound/outgoing.conf" || 
			#unbound-control dump_cache > /etc/unbound/cache.file && success "$(date) - Backed up unbound cache to /etc/unbound/cache.file" || error "$(date) - Failed to backup unbound cache to /etc/unbound/cache.file"
			#unbound-control reload && success "$(date) - Reload unbound" || error "$(date) - Failed to reload unbound"
			#unbound-control load_cache < /etc/unbound/cache.file && success "$(date) - Loaded unbound cache from /etc/unbound/cache.file" || error "$(date) - Failed to load unbound cache from /etc/unbound/cache.file"
			service unbound restart
		fi

		#CURRENTMETRIC=$(route -n | grep 'UG' | grep "$INTERFACE" | awk '{printf "%s\n",$5}')
		#NEWMETRIC=$(( $tablenum + 1000 ))

		#if [ "$CURRENTMETRIC" == "$NEWMETRIC" ]; then
		#	warning "$(date) - $INTERFACE - Metric already set to: 1${tablenum}"
		#else
		#	# Set metric higher since we have loss or high latency
		#	#/sbin/dhcpcd -m 1"${tablenum}" "$INTERFACE" && success "$(date) - $INTERFACE - DHCPCD Metric set to: 1${tablenum}" || fatal "$(date) - $INTERFACE - Failed to set metric to: 1${tablenum}"
		#	ifmetric "$INTERFACE" 1"${tablenum}" && success "$(date) - $INTERFACE - IFMETRIC set to: 1${tablenum}" || fatal "$(date) - $INTERFACE - Failed to set metric to: 1${tablenum}"
		#fi
	fi

	sleep "$WAITSEC"

done

###############################################################################################################
# REMOVE LOCK                                                                                                 #
###############################################################################################################
if [ -f /tmp/.script_lock_"$INTERFACE" ]; then
    rm /tmp/.script_lock_"$INTERFACE" && success "$(date) - $INTERFACE $IP - Removed lock file" || fatal "$(date) - $INTERFACE $IP - Failed to remove lock file"
fi

###############################################################################################################
# END                                                                                                         #
###############################################################################################################
success "$(date) - $INTERFACE $IP - Script finished - $COUNTER Warning(s) and / or error(s)"

exit 0
