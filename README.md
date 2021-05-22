# mitim_userscripts
Man in the middle users scripts for iPads and iPhones with browsers that don't have userscript support.


Use the mitmproxy project to install mitm root certificates on the target ipad or iphone.

Direct trafic to the server using iptables

### Example iptables rules and /etc/hosts
```
# combine this rule with a dns entry to only rewrite requests certain to hosts
-A PREROUTING -p tcp -i $INTIF -d 10.100.222.111 --dport 443 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j DNAT --to-destination 192.168.1.2:8190

# to rewite all requests from a certain host in the network (like your ipad)
-A PREROUTING -p tcp -i $INTIF -s 192.168.1.45 --dport 443 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j DNAT --to-destination 192.168.1.2:8190
```

/etc/host example to insert a user script in to youtube
```
10.100.222.222 youtube.com
10.100.222.222 www.youtube.com
10.100.222.222 youtube-ui.l.google.com
```



