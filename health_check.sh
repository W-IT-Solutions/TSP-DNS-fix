#!/bin/bash
# shellcheck disable=SC2015,SC2004
# Jan 6 2022 - scripting@waaromzomoeilijk.nl
#
# This is a leftover from dpinger testing to fix the interfaces not being managed by their performance/state
# For reference

################################ Logger
INTERACTIVE="0" # 1 = on / 0 = off - Log all script output to file (0) or just output everything in stout (1)
if ! [ "$INTERACTIVE" == 1 ]; then 
    LOGFILE="/var/log/health_check.log" # Log file
    exec 3>&1 4>&2
    trap 'exec 2>&4 1>&3' 0 1 2 3 15 RETURN
    exec 1>>"$LOGFILE" 2>&1
fi

################################ CMD line output
print_text_in_color() {
	/usr/bin/printf "%b%s%b\n" "$INTERFACE" "$2" "$Color_Off"
}
Color_Off='\e[0m'   # Text Reset
IRed='\e[0;91m' 		# Red
IGreen='\e[0;92m'   # Green
IYellow='\e[0;93m'  # Yellow
IBlue='\e[0;94m'		# Blue
ICyan='\e[0;96m'		# Cyan

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
	if [ -f /tmp/.script_lock_"$INTERFACE" ]; then
		rm -rf /tmp/.script_lock_"$INTERFACE" && success "$(date) - $INTERFACE - Removed /tmp/.script_lock_$INTERFACE prematurely" || fatal "$(date) - $INTERFACE - Failed to remove /tmp/.script_lock_$INTERFACE"
	fi
	exit 1
}

################################ Check / Set lock
#if [ -f /tmp/.script_lock_"$1" ]; then
#    error "$(date) - $1 - Script is already running"
#	exit 1
#else
#    touch /tmp/.script_lock_"$1" && start "$(date) - $1 - Created /tmp/.script_lock_$1" || fatal "$(date) - $1 - Failed to create /tmp/.script_lock_$1"
#fi

################################ Interface parameter check
start "$(date) - $1 - Health check initiated"
if [ -n "$1" ]; then
	INTERFACE="$1"
	success "$(date) - $INTERFACE - Interface parameter detected"
else
	fatal "$(date) - Interface parameter not detected"
fi

################################ Vars and functions
DEBUG="0" # 1 = on / 0 = off
IP=$(ip address show dev "$INTERFACE" | grep inet | head -1 | awk '{printf "%s\n",$2}' | sed 's|/24||g')
#GW='192.168.8.1'
#NETWORK='192.168.8' # Leave OUT the last dot and octet 
#LOG='/var/log/if_down_checker.log'
#WAITSEC="60" # Loop time, every 10 seconds
#CURLTIMEOUT="20" 
METRIC=$(route -n | grep 'UG' | grep "$INTERFACE" | awk '{printf "%s\n",$5}')
octet=$(ip address show dev "$INTERFACE" | grep inet | awk -F "[/.]" '{print $4;}')
tablenum=$(( $octet + 100 ))

# Dpinger vars
# CHECK OTHER VAR $1 FROM SYSTEMD DPINGER CMD
dest_addr="$2"
alarm_flag="$3"
latency_avg="$4"
loss_avg="$5"

# Check IP var
if [ -n "$IP" ]; then
	success "$(date) - $INTERFACE - IP variable detected"
else
	fatal "$(date) - $INTERFACE - IP variable not detected"
fi

################################ Stock snippits
# && success "$(date) - $INTERFACE - INIT - Debug set" || fatal "$(date) - $INTERFACE - INIT - Setting debug failed"

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
		set -ex && success "$(date) - $INTERFACE - INIT - Debug set" || error "$(date) - $INTERFACE - INIT - Setting debug failed"
	fi
}

################################ Pre
debug_mode
root_check

################################ Check / Set lock
if [ -f /tmp/.script_lock_"$1" ]; then
    	error "$(date) - $1 - Script is already running"
	exit 1
else
    	touch /tmp/.script_lock_"$1" && start "$(date) - $1 - Created /tmp/.script_lock_$1" || fatal "$(date) - $1 - Failed to create /tmp/.script_lock_$1"
fi

################################ Delete routes
#ip route delete default via "$GW" dev "$INTERFACE" src "$IP" && success "$(date) - $INTERFACE - Deleted routes for $INTERFACE" || fatal "$(date) - $INTERFACE - Failed to delete routes for $INTERFACE"
#route -vF del -net "$NETWORK".0/24 gw 0.0.0.0 
#ip rule del from "$NETWORK"."${octet}" table "${tablenum}"

################################ Bring down the interface
#ip link set "$INTERFACE" down && success "$(date) - $INTERFACE - $INTERFACE is brought down" || fatal "$(date) - $INTERFACE - Failed to bring down $INTERFACE"

################################ Set metric higher since we have loss or high latency
dhcpcd -m 10"${tablenum}" "$INTERFACE" && success "$(date) - $INTERFACE - Metric set to: 10${tablenum}" || fatal "$(date) - $INTERFACE - Failed to set metric to: 10${tablenum}"

################################ Automate based on alert_flag
# the alert_cmd is invoked as "alert_cmd dest_addr alarm_flag latency_avg loss_avg"
# alarm_flag is set to 1 if either latency or loss is in alarm state
# alarm_flag will return to 0 when both have have cleared alarm state
#if [ "$alarm_flag" -eq 1 ]; then
#    my_alarm_cmd 
#else
#    my_clear_cmd # "$dest_addr" "$latency_avg" "$loss_avg"
#fi


################################ Loop checking for connectivity and adding routes on downed interface
while :
do
	header "$(date) - $INTERFACE - Loop, checking for connectivity"
	# Bring the interface up again in order to test for a connection
	#ip link set "$INTERFACE" up && success "$(date) - $INTERFACE - is brought up" || fatal "$(date) - $INTERFACE - Failed to bring up $INTERFACE"	
	
	# Check the loss % on the interface
	CONNECTION=$(cat "/tmp/health_$INTERFACE" | awk '{print $3}')

	if [ "$CONNECTION" -lt "0"; then
			#ip route add default via "$GW" dev "$INTERFACE" src "$NETWORK"."$octet" table "$tablenum" && success "$(date) - $INTERFACE - Added routes for $INTERFACE" || fatal "$(date) - $INTERFACE - Failed to add routes for $INTERFACE"
			#if ! ip rule show | grep -q "$NETWORK.${octet}"; then
				#ip rule add from "$NETWORK"."${octet}" table "${tablenum}" && success "$(date) - $INTERFACE - Added routes for $INTERFACE" || fatal "$(date) - $INTERFACE - Failed to add routes for $INTERFACE"
		    	#fi

			# Loss is 0% set original metric value back
			dhcpcd -m "$METRIC" "$INTERFACE" && success "$(date) - $INTERFACE - Metric set to old value of: $METRIC" || fatal "$(date) - $INTERFACE - Failed to set metric to old value of: $METRIC"
			dhcpcd -n "$INTERFACE"
			
			# Abandon the loop.
			success "$(date) - $INTERFACE - Break the loop"
			break 
	else

		#ifconfig "$INTERFACE" down && error "$(date) - $INTERFACE - $INTERFACE is brought down, still no connection" || fatal "$(date) - $INTERFACE - Failed to bring down $INTERFACE"
  	fi

	header "$(date) - $INTERFACE - Eat, sleep, bash, repeat"
	sleep "$WAITSEC"
done

################################ Remove lock
if [ -f /tmp/.script_lock_"$INTERFACE" ]; then
    rm /tmp/.script_lock_"$INTERFACE" && success "$(date) - $INTERFACE - Removed lock file" || fatal "$(date) - $INTERFACE - Failed to remove lock file"
fi

# End of script
success "$(date) - Script finished - $COUNTER Warning(s) and / or error(s)"
cat /var/log/health_check_script_errors_warnings.log

exit 0
