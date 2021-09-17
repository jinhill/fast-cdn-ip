##Fast Cloudflare IP
This script helps you get the fastest cf ip.

#Features:
1) Support ipv4 and ipv6 of the Cloudflare.
2) This script tests your own server speed, and you will get the most suitable IP. Comparing with other scripts, testing other services does not mean that it is the best result.
3) This script can also execute custom programs for you, so that you can update your DNS records after obtaining the optimal IP.

#Usage:
./cf-ip.sh [-4/6] [-p <num>] [-d <num>] [-f <num>] [-c <command>]
./cf-ip.sh [-t] [-n <dns server>] [-r <url>] [-a <ip address/masquerade host list>]
	-4/6 Get ipv4 or ipv6;
	-p Generate random ip addresses number for ping test;
	-d Set the number of ip addresses for the download test;
	-f Set the fastest number of ip addresses returned;
	-c Set the post execution command, Internal variable {{FAST_V4_IPS}} & {{FAST_V6_IPS}} can be used;
	-t Test current ip speed;
	-n Set dns server for test download speed;
	-a Set dns resolution ip addresses or masquerade host name list for the host of url;
	-r Set url to test download speed;
	-h Print help.

./cf-ip.sh -p 200 -d 10 -f 1 -r 'https://cdn.yourdomain.com/download/xxx.zip' -c 'echo "update this ipv4: {{FAST_V4_IPS}} ipv6: {{FAST_V6_IPS}} to ddns."'

./cf-ip.sh \
	-p 200 \
	-d 10 \
	-f 1 \
	-r 'https://cdn.yourdomain.com/download/xxx.zip' \
	-c 'curl -X PUT "https://api.cloudflare.com/client/v4/zones/${YOUR_ZONE_ID}/dns_records/${DNS_RECORD_ID}" \
     -H "X-Auth-Email: ${USER_EMAIL}" \
     -H "X-Auth-Key: ${AUTH_KEY}" \
     -H "Content-Type: application/json" \
     --data '"'"'{"type":"A","name":"fast.example.com","content":"{{FAST_V4_IPS}}","ttl":120,"proxied":false}'"'"
