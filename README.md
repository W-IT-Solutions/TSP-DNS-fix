# TSP-DNS-fix
`DNSPI.sh` Installs unbound DNS caching server, listining on all interfaces + DNS over TLS (Cloudflare) + outgoing DNS queries on all interfaces and let the system use unbound as its primary DNS server https://www.cloudflare.com/learning/dns/dns-over-tls/

Unbound will bind to all INTERFACEIP:53 (check with `ss -tunlp | grep ':53'`) and will respond to requests on each interface. Thus always having multiple outbound routes for DNS resolving.
when the ttl expires on a domain, unbound will do an automated lookup to refresh the cache and thus speeding up future lookups to that domain.

As long as `nameserver 127.0.0.1` is in `/etc/resolv.conf`  and the `DNS=` option in `/etc/systemd/resolved.conf` is set to `DNS=127.0.0.1`, the system is able to resolve domain names no matter if the main interface is down (and thus other commands to the WWW will fail)

Unbound needs to build up a cache of results before it starts to speed up.
When you browse websites you make dozens of DNS queries for different resources (JavaScript, CSS, etc). 
Lots of these libraries are commonly used across multiple websites.
Unbound will soon learn where those resources are and won't have to do a full lookup every time.


# Problem
When the main metric interface is down, by connOff.sh or LTE endpoint failure, the default routes for that interface are still in place but, obviously not working. 
When not changing the metric of the failing interface, the system will use the IP setup on that interface for outgoing requests, thus will fail no matter what. 

Its not possible to send traffic out all interfaces at once, for this we'd need bonding, also an option though.

## Solution
For now we're able to do lookups even when the main interface is down on each interface that is up.
we monitor the interface state with dpinger which writes the values and a systemd script checks those and adds or removes outgoing-interfaces from unbound.conf automatically based on link status. End result, always a working DNS resolver.

In order have a connection again on the file system when the main interface is down, we can use dpinger and the same script to add (+1000) metric to interfaces that are down. In turn when the interface is up deduct (-1000) from the metric and the interface is add to the 'working interface pool' again.

## Commands to verify workings unbound
Notice the query time in the dig commands, if its a good hit and has a time of 0, it is served from cache.
So to properly test DNS resolving either clear the cache or query a new domain that is not cached yet.
Every interface that is up and has a proper LTE connection is able to do lookups on `INTERFACEIP:53`
`dig -p 53 facebook.com @192.168.8.11`

### Make query to unbound that in turn tries all available interfaces
`dig -p 53 facebook.com @127.0.0.1`

## Flush unbound cache
`unbound-control flush`
`unbound-control flush domain.com`

# Download the script, inspect it, adjust variable's and run
`wget https://raw.githubusercontent.com/WaaromZoMoeilijk/TSP-DNS-fix/main/install.sh`

`nano install.sh`

`bash install.sh`


## showcase of working DNS with main interface down:
```
############ root@raspberry:~# route -n
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         192.168.8.1     0.0.0.0         UG    204    0        0 enp3s0u1u4u4u3
0.0.0.0         192.168.8.1     0.0.0.0         UG    206    0        0 enp3s0u1u4u4u1
0.0.0.0         192.168.8.1     0.0.0.0         UG    209    0        0 enp3s0u1u4u1
0.0.0.0         192.168.8.1     0.0.0.0         UG    210    0        0 enp3s0u1u4u2
0.0.0.0         192.168.8.1     0.0.0.0         UG    211    0        0 enp3s0u1u4u4u4
0.0.0.0         192.168.8.1     0.0.0.0         UG    212    0        0 enp3s0u1u1
0.0.0.0         192.168.8.1     0.0.0.0         UG    213    0        0 enp3s0u1u2
0.0.0.0         192.168.8.1     0.0.0.0         UG    214    0        0 enp3s0u1u3
100.70.0.0      0.0.0.0         255.255.0.0     U     0      0        0 tun4806
100.70.0.0      0.0.0.0         255.255.0.0     U     0      0        0 tun4805
100.70.0.0      0.0.0.0         255.255.0.0     U     0      0        0 tun4801
192.168.8.0     0.0.0.0         255.255.255.0   U     204    0        0 enp3s0u1u4u4u3
192.168.8.0     0.0.0.0         255.255.255.0   U     206    0        0 enp3s0u1u4u4u1
192.168.8.0     0.0.0.0         255.255.255.0   U     209    0        0 enp3s0u1u4u1
192.168.8.0     0.0.0.0         255.255.255.0   U     210    0        0 enp3s0u1u4u2
192.168.8.0     0.0.0.0         255.255.255.0   U     211    0        0 enp3s0u1u4u4u4
192.168.8.0     0.0.0.0         255.255.255.0   U     212    0        0 enp3s0u1u1
192.168.8.0     0.0.0.0         255.255.255.0   U     213    0        0 enp3s0u1u2
192.168.8.0     0.0.0.0         255.255.255.0   U     214    0        0 enp3s0u1u3
192.168.193.0   0.0.0.0         255.255.255.0   U     0      0        0 zt7nnpq7z3

############ root@raspberry:~# ping -I enp3s0u1u4u4u3 1.1.1.1 # verify we don't have a connection on the main metric interface
PING 1.1.1.1 (1.1.1.1) from 192.168.8.17 enp3s0u1u4u4u3: 56(84) bytes of data.
From 192.168.8.1 icmp_seq=1 Destination Net Unreachable
^C
--- 1.1.1.1 ping statistics ---
1 packets transmitted, 0 received, +1 errors, 100% packet loss, time 0ms

############ root@raspberry:~# dig -p 53 coolblue.nl @127.0.0.1

; <<>> DiG 9.11.5-P4-5.1+deb10u6-Debian <<>> -p 53 coolblue.nl @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 31796
;; flags: qr rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1472
;; QUESTION SECTION:
;coolblue.nl.			IN	A

;; ANSWER SECTION:
coolblue.nl.		600	IN	A	18.64.115.45
coolblue.nl.		600	IN	A	18.64.115.79
coolblue.nl.		600	IN	A	18.64.115.101
coolblue.nl.		600	IN	A	18.64.115.59

;; Query time: 388 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Mon Jan 31 17:27:37 IST 2022
;; MSG SIZE  rcvd: 104

############ root@raspberry:~# dig -p 53 jumbo.nl @192.168.8.11

; <<>> DiG 9.11.5-P4-5.1+deb10u6-Debian <<>> -p 53 jumbo.nl @192.168.8.11
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 3272
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1472
;; QUESTION SECTION:
;jumbo.nl.			IN	A

;; ANSWER SECTION:
jumbo.nl.		3600	IN	A	37.46.140.12
jumbo.nl.		3600	IN	A	34.213.106.51

;; Query time: 571 msec
;; SERVER: 192.168.8.11#53(192.168.8.11)
;; WHEN: Mon Jan 31 17:28:07 IST 2022
;; MSG SIZE  rcvd: 69
```
