Fast Cloudflare IP<br>
This script helps you get the fastest cf ip.<br>
Usage:<br>
./cf-ip.sh [-4/6] [-p <num>] [-d <num>] [-f <num>] [-c <command>]<br>
./cf-ip.sh [-t] [-n <dns server>] [-r <url>] [-a <ip address list>]<br>
	-4/6 Get ipv4 or ipv6, if not set, intelligent support ipv6;<br>
	-p Generate random IP addresses number for ping test;<br>
	-p Generate random IP addresses number for ping test;<br>
	-d Set the number of IP addresses for the download test;<br>
	-f Set the fastest number of IP addresses returned;<br>
	-c Set the post execution command, Internal variable {{FAST_V4_IPS}} & {{FAST_V6_IPS}} can be used;<br>
	-t Test current IP speed;<br>
	-n Set dns server for test download speed;<br>
	-a Set dns resolution ip address list for the host of url;<br>
	-r Set url to test download speed;<br>
	-h Print help.<br>
<br>
./cf-ip.sh -4 -p 200 -d 10 -f 1 -c 'echo "update this ip {{FAST_V4_IPS}} to ddns."'<br>
