#!/bin/bash
# Clear outgoing interfaces
MAINETHNIC="enp0s31f6"
SCRIPTS="/var/scripts"

cat /dev/null > /etc/unbound/outgoing.conf
cat /dev/null > /tmp/interfaces

readarray -t interfaces < <(ip l | grep enp | grep -v "$MAINETHNIC" | awk '{printf "%s\n",$2}' | sed 's/://g' | sed -r '/^\s*$/d' | cut -f1 -d"@")
for i in "${interfaces[@]// /}" ; do 
    echo "$i" >> /tmp/interfaces 
done

readarray -t interfaces < <(cat /tmp/interfaces)
for INTERFACE in "${interfaces[@]// /}" ; do 
    IP=$(ip address show dev "$INTERFACE" | grep inet | head -1 | awk '{printf "%s\n",$2}' | sed 's|/24||g')
    if [ -z "$IP" ]; then
        error "$(date) - Setup Unbound - No IP on $INTERFACE"
    else
        echo "outgoing-interface: $IP" >> /etc/unbound/outgoing.conf
        echo "outgoing-interface: $IP" >> "$SCRIPTS"/outgoing.conf
    fi
done

unbound-control reload

exit 0
