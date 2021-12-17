logforj
=======

Block Log4J/Log4Shell attacks from leaving your network

The Log4J/Log4Shell attack is a trivial and pervasive vector to remote code execution which affects many systems. Many applications may indirectly rely on Log4j (via pulled in libraries or 'statically' built applications that use it). Getting an entire software estate updated in good time before being hit remains a challenge to many systems administrators, developers and engineers.

Logforj is basically a network side sticking-plaster / workaround which can be deployed to protect networks and hosts from these types of attacks until a software estate can be properly tackled.

# An alternative approach 

Rather than prevent bad requests from arriving on a vulnerable application, Logforj protects the outbound layer of the network by detecting, reporting and blocking the executed _${jndi:...}_ requests that vulnerable applications will perform by analyzing the layer 7 traffic that makes up these requests.

Logforj will currently detect the following types of traffic:
- LDAP
- JRMP

Logforj works off of the assumption that LDAP and JRMP traffic on random ports out to the internet are probably suspect.

Logforj works best being placed on a gateway or border device, such that is can protect the many devices behind it.

Requirements
------------

Logforj runs on Linux (probably greater than 3.1) and requires netfilter with connection tracking enabled.
Logforj needs **cap_net_admin** capabilities on the binary to properly function.

# Implementation

Logforj uses netfilter queues to analyze the traffic and make a traffic decision based on the data seen. If a suspicious message is detected, the packet gets marked for netfilter rules to later drop, report or do something else with.

Logforj doesn't rely on port numbers to work out the data but heuristically determines the protocol type based off of the layer 7 traffic.

# Performance

Logforj only cares about the beginning on any TCP session, since it detects the beginning headers of LDAP and JRMP sessions. Once a connection has been analyzed, its connection is marked as _seen_ and the firewall rule need not send Logforj more data for that connection again. This prevents large amounts of traffic needing to be sent to the software.

Getting Started
---------------

You will need to be running a firewall (either nftables or iptables) on the host or network you want to protect.

Be aware -- logforj cannot determine the difference between legitimate LDAP traffic and illegitimate.

A minimal nftables configuration might look like:
```
# Add a new table, this makes it much easier to manage logforj independently.
nft add table inet logforj;

# Add new chains, make it above the normal priority by a bit this ensures the normal table runs first and pre-filters any traffic
nft add chain inet logforj forward '{ type filter hook forward priority 1; policy accept; }'
nft add chain inet logforj output  '{ type filter hook output priority 1; policy accept; }'

# Create the queue rule to attach to logforj
# Note we dont distinguish on port number given these attacks generally attempt to connect to random outbound port numbers or well-known to be open ones like port 53.
# In this case, we only check traffic heading outbound:
# - which outbound interface faces the internet directly.
# - Is only TCP traffic.
# - We dont want traffic already analyzed by the program (set with connection tracking mark 9)
# - We only want established connections (we aren't interested in the 3 way handshake at the TCP session start)
# If these match, push into netfilter queues 10-13 (4 queues).
# - Bypass means to ignore this rule and continue on in the case logforj is not running
# - fanout will spread out matching traffic between 4 queues
nft add rule inet logforj forward oifname { eth0, eth1 } meta l4proto tcp ct mark != 9 ct state established queue num 10-13 bypass fanout
nft add rule inet logforj output oifname { eth0, eth1 } meta l4proto tcp ct mark != 9 ct state established queue num 10-13 bypass fanout

# Create the 'action' rule above it on how to deal with detected traffic
# If you reject with a tcp-reset the affected application would 'exit gracefully'
# and you wont be left with a hung application thread.
nft insert rule inet logforj forward meta mark 10 log prefix '"log4j attack "' counter reject with tcp reset
nft insert rule inet logforj output meta mark 10 log prefix '"log4j attack "' counter reject with tcp reset
```

Next, start the process. (logforj creates one worker thread per queue).
```
logforj --seen-mark=9 --bad-mark=10 --queue=10 --queue-size=4
2021-12-17 09:32:49: (config) Starting logforj --seen-mark=9 --bad-mark=10 --queue=10 --queue-size=4
2021-12-17 09:32:49: (logforj) Starting logforj
...
...
2021-12-17 12:57:58: (heuristics) Marked Suspicious packet: 192.168.5.7 port 34426 -> 172.245.17.111 port 12345 : LDAP: BIND request message type detected.
```

Attempts outbound to perform LDAP requests should now fail. Note, that you can successfully make connections to these hosts, however attemping LDAP traffic or JRMP traffic should fail.

IE:
```
# With logforj running and blocking traffic to a public LDAP server
$ telnet www.zflexldap.com 389
Trying 172.245.17.111...
Connected to www.zflexldap.com.
Escape character is '^]'.
HELLO WORLD!
^]

telnet> quit
Connection closed.

$ ldapsearch -w test -D cn=ro_admin,ou=sysadmins,dc=zflexsoftware,dc=com -H "ldap://www.zflexldap.com/"
ldap_result: Can't contact LDAP server (-1)
```

Ultimately you can use any IPTables rule (see `-j QUEUE`) or nftables rules you like to whitelist hosts or only ensure checks are performing only on certain interfaces.
