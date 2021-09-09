Fast Cloudflare IP
This script helps you get the fastest cf ip.
Usage:
./cf-ip.sh [-4/6] [-p <num>] [-d <num>] [-f <num>] [-c <command>]
./cf-ip.sh [-t] [-n <dns server>] [-r <url>] [-a <ip address list>]
	-4/6 Get ipv4 or ipv6, if not set, intelligent support ipv6;
	-p Generate random IP addresses number for ping test;
	-p Generate random IP addresses number for ping test;
	-d Set the number of IP addresses for the download test;
	-f Set the fastest number of IP addresses returned;
	-c Set the post execution command, Internal variable {{FAST_V4_IPS}} & {{FAST_V6_IPS}} can be used;
	-t Test current IP speed;
	-n Set dns server for test download speed;
	-a Set dns resolution ip address list for the host of url;
	-r Set url to test download speed;
	-h Print help.

./cf-ip.sh -4 -p 200 -d 10 -f 1 -c 'echo "update this ip {{FAST_V4_IPS}} to ddns."'