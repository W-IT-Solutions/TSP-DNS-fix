#!/bin/bash
# Clear outgoing interfaces
MAINETHNIC=

cat /dev/null > /etc/unbound/outgoing.conf
cat /dev/null > /tmp/interfaces

sleep 45

readarray -t interfaces < <(ip l | grep enp | grep -v "$MAINETHNIC" | awk '{printf "%s\n",$2}' | sed 's/://g' | sed -r '/^\s*$/d' | cut -f1 -d"@")
for i in "${interfaces[@]// /}" ; do 
    echo "$i" >> /tmp/interfaces 
done

readarray -t interfaces < <(cat /tmp/interfaces)
for INTERFACE in "${interfaces[@]// /}" ; do
    IP=$(ip address show dev "$INTERFACE" | grep inet | head -1 | awk '{printf "%s\n",$2}' | sed 's|/24||g')
    if [ -z "$IP" ]; then
        echo "$(date) - Setup Unbound - No IP on $INTERFACE" && exit 1
    else
        echo "outgoing-interface: $IP" >> /etc/unbound/outgoing.conf
        echo "IPv4"
    fi
done

# check that there will be no IPV6 addresses present
sed -i /::/d /etc/unbound/outgoing.conf

service unbound restart

exit 0
