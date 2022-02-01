#!/bin/bash 
# shellcheck disable=SC2015,SC2002
# Jan 6 2022 - scripting@waaromzomoeilijk.nl
#
################################ Logger
INTERACTIVE="0" # 1 Foreground / 0 = Background - Log all script output to file (0) or just output everything in stout (1)
if ! [ $INTERACTIVE == 1 ]; then 
    LOGFILE="/var/log/unbound-check.log" # Log file
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
COUNTER="0"
FAILS="0"
SUCCESS="0"
UNBOUNDRESET="0"

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
    /bin/echo -e "${IYellow} $* ${Color_Off}" >> /var/log/unbound-check-err.log   
}
error() {
	/bin/echo -e "${IRed} $* ${Color_Off}" >&2
  	/bin/echo -e "${IRed} $* ${Color_Off}" >> /var/log/unbound-check-err.log   
}
header() {
	/bin/echo -e "${IBlue} $* ${Color_Off}" >&2
}
fatal() {
	/bin/echo -e "${IRed} $* ${Color_Off}" >&2
    /bin/echo -e "${IRed} $* ${Color_Off}" >> /var/log/unbound-check-err.log    
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

################################ If flush, lookup matches IP then it works, else if 5 fails, dump cache, reload, load cache and continue
while :
do 
    QUERYTIME=$(cat /tmp/.unbound-check | grep 'Query time:' | sed 's|;; ||g')
    # STATUS=$(cat /tmp/.unbound-check | head -5 | tail -1 | awk '{print $6}' | sed 's|,||g')
    unbound-control -q flush bol.com ; dig bol.com > /tmp/.unbound-check

    if grep -q '185.14.169.113' /tmp/.unbound-check ; then
        SUCCESS=$((SUCCESS+1))
        success "$(date) - Cache flushed, IP matches, resolving works!"
        success "$(date) - $QUERYTIME. Working attempts: $SUCCESS. Failed attempts: $FAILS. Total unbound reloads: $UNBOUNDRESET"
        COUNTER="0"
    else
        COUNTER=$((COUNTER+1))
        FAILS=$((FAILS+1))

        error "$(date) - Something went wrong, could not detect a proper IP for domain check"

        #if [ "$COUNTER" -gt "5" ]; then
        #    COUNTER="0"
        #    unbound-control dump_cache > /etc/unbound/cache.file && success "$(date) Backed up unbound cache to /etc/unbound/cache.file" || error "$(date) - Failed to backup unbound cache to /etc/unbound/cache.file"
        #    unbound-control reload && success "$(date) - Reload unbound" || error "$(date) - Failed to reload unbound"
        #    UNBOUNDRESET=$((UNBOUNDRESET+1))
        #    sleep 0.5
        #    unbound-control load_cache < /etc/unbound/cache.file && success "$(date) - Loaded unbound cache from /etc/unbound/cache.file" || error "$(date) - Failed to load unbound cache from /etc/unbound/cache.file"
        #fi
        
        error "$(date) - $QUERYTIME. Working attempts: $SUCCESS. Failed attempts: $FAILS. Total unbound reloads: $UNBOUNDRESET"
    fi
    sleep 5 
    # break
done