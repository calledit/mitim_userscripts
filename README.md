# mitim_userscripts
Man in the middle users scripts for iPads and iPhones with browsers that don't have userscript support.


Use the mitmproxy project to install certificates to the target ipad or iphone.

Direct trafic to the server using iptables
### Example iptables rules
```

# combine this rule with a dns entry to only rewrite requests certain hosts
-A PREROUTING -p tcp -i $INTIF -d 10.100.222.111 --dport 443 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j DNAT --to-destination 192.168.1.2:8190

# to rewite all data from a certaein host in the network (like your ipad)
-A PREROUTING -p tcp -i $INTIF -s 192.168.1.45 --dport 443 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j DNAT --to-destination 192.168.1.2:8190
```



