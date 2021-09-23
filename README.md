##Fast Cloudflare IP</br>
This script helps you get the fastest cf ip.</br>
</br>
#Features:</br>
1) Support ipv4 and ipv6 of the Cloudflare.</br>
2) This script tests your own server speed, and you will get the most suitable IP. Comparing with other scripts, testing other services does not mean that it is the best result.</br>
3) This script can also execute custom programs for you, so that you can update your DNS records after obtaining the optimal IP.</br>
</br>
#Usage:</br>
```
./cf-ip.sh [-4/6] [-p <num>] [-d <num>] [-f <num>] [-c] [-v] [-s <shell/command>]
./cf-ip.sh [-t] [-n <dns server>] [-r <url>] [-a <ip address/masquerade host list>]
    -4/6 Get ipv4 or ipv6;
    -a Set dns resolution ip addresses or real host name list for the host of url;
    -c Compare the fastest speed with the existing ip speed;
    -d Set the number of ip addresses for the download test;
    -f Set the fastest number of ip addresses returned;
    -n Set dns server for test download speed;
    -p Generate random ip addresses number for ping test;
    -r Set url to test download speed;
    -s Set the post execution shell or command, internal variable {{FAST_V4_IPS}} & {{FAST_V6_IPS}} can be used;
    -t Test current ip speed;
    -v Version of this script;
    -h Print help.
```
</br>

#sample1:update_dns.sh
```
#! /bin/sh
# update dns records to the local dnsmasq service.
ipv4="$1"
ipv6="$2"
if [ -n "$ipv4" ];then
	#replace [ \n] to ','
	ipv4_s=$(echo "$ipv4" | sed -e ':a; ;$!ba;s/ /,/g' -e ':a;N;$!ba;s/\n/,/g')
	dnsmasq --host-record=fast.cloudflare.lan,"${ipv4_s}"
fi
if [ -n "$ipv6" ];then
	ipv6_s=$(echo "$ipv6" | sed -e ':a; ;$!ba;s/ /,/g' -e ':a;N;$!ba;s/\n/,/g')
	dnsmasq --host-record=fast6.cloudflare.lan,"${ipv6_s}"
fi
#After the update, do some restart services as needed.
#systemctl restart your-service
```
`./cf-ip.sh -p 200 -d 10 -f 2 -r 'https://cdn.yourdomain.com/download/xxx.zip' -c -a 'fast.cloudflare.lan fast6.cloudflare.lan' -s '/path/to/update_dns.sh "{{FAST_V4_IPS}}" "{{FAST_V6_IPS}}"'`</br>
Replace parameters of -r and -s with your own before running. Then you can use 'fast.cloudflare.lan' or 'fast6.cloudflare.lan' in your app, but it has to be used in the intranet. You can also use scripts to update dns on Cloudflare, Aliyun, etc.</br>
</br>
#sample2:update_cf_dns.sh
```
#! /bin/sh
# update dns records to cloudflare.
YOUR_ZONE_ID="XXX"
DNS_RECORD_ID="XXX"
DNS6_RECORD_ID="XXX"
USER_EMAIL="you@domain.com"
AUTH_KEY="XXX"
ipv4="$1"
ipv6="$2"
if [ -n "$ipv4" ];then
	curl -X PUT "https://api.cloudflare.com/client/v4/zones/${YOUR_ZONE_ID}/dns_records/${DNS_RECORD_ID}" \
	     -H "X-Auth-Email: ${USER_EMAIL}" \
	     -H "X-Auth-Key: ${AUTH_KEY}" \
	     -H "Content-Type: application/json" \
	     --data '{"type":"A","name":"fast.yourdomain.com","content":"${ipv4}","ttl":120,"proxied":false}'
fi
if [ -n "$ipv6" ];then
	curl -X PUT "https://api.cloudflare.com/client/v4/zones/${YOUR_ZONE_ID}/dns_records/${DNS6_RECORD_ID}" \
	     -H "X-Auth-Email: ${USER_EMAIL}" \
	     -H "X-Auth-Key: ${AUTH_KEY}" \
	     -H "Content-Type: application/json" \
	     --data '{"type":"AAAA","name":"fast6.yourdomain.com","content":"${ipv6}","ttl":120,"proxied":false}'
fi
```
`./cf-ip.sh -p 200 -d 10 -f 1 -r 'https://cdn.yourdomain.com/download/xxx.zip' -c -a 'fast.yourdomain.com fast6.yourdomain.com' -s '/path/to/update_cf_dns.sh "{{FAST_V4_IPS}}" "{{FAST_V6_IPS}}"'`
