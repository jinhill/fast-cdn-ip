#! /bin/sh
#####################################################################
# Copyright (C) 2020 Jinhill
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#####################################################################

USER_AGENT='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'
alias _CURL='curl -s -H "user-agent: $USER_AGENT" -H "accept: text/html;*/*"'
#SPEED_TEST_URL="https://cdn.yourdomain.com/download/100mb.zip"
SPEED_TEST_URL="https://speed.cloudflare.com/__down?bytes=100000000"
CF_IPV4_URL="https://www.cloudflare.com/ips-v4"
CF_IPV6_URL="https://www.cloudflare.com/ips-v6"
CF_IPV6_RANGE="2606:4700::/96 2606:4700:3031::/96 2606:4700:3032::/96 2606:4700:3033::/96"
IPV6_TEST_URL="https://ipv6-test.com"
DEFAULT_PING_COUNT=100
DEFAULT_DL_SPEED_COUNT=6
DEFAULT_FAST_COUNT=2
DEFAULT_DNS=119.29.29.29
_debug(){
	echo "$@" 1>&2
}

_log(){
	printf "$@" 1>&2
}

_log_f(){
	printf "$@" >> /var/log/cf-ip.log
}

#$1:string,$2:char,$ret:count
_count() {
  echo "$1" | awk -F"$2" '{print NF-1}'
}

#$1:dommain,$2:dns server
_get_dns(){
	#need dnsutils
	resolve_cmd=nslookup
	head_line=3
	if [ $(command -v host) ];then
		#debain
		resolve_cmd=host
		if [ -z "$2" ];then
			head_line=1;
		fi
	fi
	$resolve_cmd "$@" | tail -n +$head_line | grep -ioE '[a-fA-F0-9:.]{7,}$'
}

hex2dec(){
	[ "$1" != "" ] && printf "%d" "$(( 0x$1 ))"
}

# expand an ipv6 address
expand_ipv6() {
	ip=$1

	# prepend 0 if we start with :
	echo $ip | grep -qs "^:" && ip="0${ip}"

	# expand ::
	if echo $ip | grep -qs "::"; then
		colons=$(echo $ip | sed 's/[^:]//g')
		missing=$(echo ":::::::::" | sed "s/$colons//")
		expanded=$(echo $missing | sed 's/:/:0/g')
		ip=$(echo $ip | sed "s/::/$expanded/")
	fi

	blocks=$(echo $ip | grep -o "[0-9a-f]\+")
	set $blocks

	printf "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n" \
	  $(hex2dec $1) \
	  $(hex2dec $2) \
	  $(hex2dec $3) \
	  $(hex2dec $4) \
	  $(hex2dec $5) \
	  $(hex2dec $6) \
	  $(hex2dec $7) \
	  $(hex2dec $8)
}

compress_ipv6() {
	echo $1 | sed -e 's/\(:0\{1,4\}\)/:/g' -e 's/:\{3,\}/::/g'
}

#$1:char,$2:count
padding(){
	printf %.s$1 `seq $2`
}

fmt_ipv6(){
	echo "$1" | sed -e 's/.\{4\}/&:/g' -e 's/:$//'
}

#remove prefix 0,00123->123
#$1:num string
_del_prefix_0(){
	rand=$1
	prefix=$(echo "$rand" | cut -b 1)
	while [ "$prefix" = "0" ];do
		rand=$(echo "$rand" | cut -b 2-)
		prefix=$(echo "$rand" | cut -b 1)
	done
	echo "$rand"
}

#$1:count,$2:min,$3:max
_gen_rand_no_repeat(){
	min=$2
	max=$3
	c=0
	no_repeat_rand=""
	r_len=$(($1*10))
	r_data=$(cat /dev/urandom | tr -dc "0123456789" | head -c$r_len)
	r_pos=1
	r_end=8
	while [ $c -lt $1 ]; do
		r=0;
		while [ $r -eq 0 ]; do
			#get rand from ram
			rand=$(echo "$r_data" | cut -b ${r_pos}-${r_end})
			r_pos=$((r_pos+8))
			r_end=$((r_end+8))
			if [ $r_end -ge $r_len ];then
				r_data=$(cat /dev/urandom | tr -dc "0123456789" | head -c$r_len)
				r_pos=1
				r_end=8
			fi
			rand=$(_del_prefix_0 "$rand")
			num=$(( ( rand % (max - min + 1 ))  + min ));
			echo "$no_repeat_rand" | grep -w "$num" >/dev/null 2>&1
			r=$?
		done
		no_repeat_rand="${no_repeat_rand} $num"
		c=$((c+1))
	done
	echo "$no_repeat_rand"
}
#$1:ip/mask,$2:ip count
_subnet() {
	local ip_range=$1
	local ip_count=$2
	local OLDIFS="$IFS"
	local sub=$(echo "$ip_range" | cut -d '/' -f 1)
	local sm=$(echo "$ip_range" | cut -d '/' -f 2)
	local mask=$(( 1 << ( 32 - sm )))
	IFS="."
		set -- $sub
		ips=$((0x$(printf "%02x%02x%02x%02x\n" $1 $2 $3 $4)))
	IFS="$OLDIFS"
	i=1;
	rand=$(_gen_rand_no_repeat $ip_count 1 $mask)
	for item in $rand;do
	  val=$((ips|item))
	  printf "%d.%d.%d.%d\n"            \
	    $(( (val >> 24) & 255 ))        \
	    $(( (val >> 16) & 255 ))        \
	    $(( (val >> 8 ) & 255 ))        \
	    $(( (val)       & 255 ))
	done
}

#$1:ipv6/mask,$2:ip count
_subnet_v6(){
	ip_c=$2
	subnet=$(echo "$1" | cut -d '/' -f 1)
	prefix=$(echo "$1" | cut -d '/' -f 2)
	subnet=$(expand_ipv6 "$subnet")
	ip_full=$(echo "$subnet" | sed "s/://g")
	pos=$((prefix / 16 * 4))
	if [ $pos -gt 0 ];then
		ip_head=$(echo "$ip_full" | cut -b -$pos)
	fi
	part=$((pos + 4))
	pos=$((pos + 1))
	ip_part=$(echo "$ip_full" | cut -b $pos-$part)
	ip_part_hex=$(( 0x$ip_part ))
	mask_part=$((prefix % 16))
	max_mask=$((0xFFFF >> $mask_part));
	min_mask=$((0xFFFF << (16 - $mask_part)));
	max_part=$((ip_part_hex | max_mask))
	min_part=$((ip_part_hex & min_mask))
	padding_len=$(( (128 - part * 4 ) / 4))
	r_len=$(( 40 * ip_c))
	r_data=$(cat /dev/urandom | tr -dc "0123456789abcdef" | head -c$r_len)
	r_pos=0
	r_end=0
	c=0
	while [ $c -lt $ip_c ]; do
		#get rand from ram
		r_pos=$((r_end + 1))
		r_end=$((r_pos + 4))
		rand=$(echo "$r_data" | cut -b ${r_pos}-${r_end})
		r_pos=$((r_end + 1))
		r_end=$((r_pos + padding_len -1))
		if [ $r_end -ge $r_len ];then
			r_data=$(cat /dev/urandom | tr -dc "0123456789abcdef" | head -c$r_len)
			r_pos=1
			r_end=$padding_len
		fi
		rand_hex=$((0x$rand))
		rand_part=$(( ( rand_hex % (max_part - min_part + 1 ))  + min_part ));
		rand_padding=$(echo "$r_data" | cut -b ${r_pos}-${r_end})
		ip=$(printf "%s%04x%s\n" "$ip_head" $rand_part "$rand_padding")
		ip=$(fmt_ipv6 "$ip")
		compress_ipv6 "$ip"
		c=$((c+1))
	done
}

#$1:ip count
_gen_cf_ips(){
	rand_ip=""
	c=$1
	ip_range=$(_CURL "$CF_IPV4_URL")
	if [ -z "$ip_range" ];then
		_log "Get cloudflare ip range error.\n"
		return 1
	fi

	ip_r_c=$(echo "$ip_range" | awk 'END{print NR}')
	sub_c=$(( c/ip_r_c + 1))
	for item in $ip_range;do
		ips=$(_subnet $item $sub_c)
		rand_ip=$(printf "%s\n%s\n" ${rand_ip} ${ips})
	done
	echo "$rand_ip"
}

#$1:ip count
_gen_cf_ipv6s(){
	c=$1
	range_c=$(_count "$CF_IPV6_RANGE" " ")
	range_c=$((range_c + 1))
	sub_c=$(( (c / range_c) + 1))
	for item in $CF_IPV6_RANGE;do
		ips=$(_subnet_v6 $item $sub_c)
		rand_ip=$(printf "%s\n%s\n" ${rand_ip} ${ips})
	done
	echo "$rand_ip"
}
#$1:ip
_get_ping_time(){
	ping_resp=$(ping -c 5 -q $1)
	lost=$(echo "$ping_resp" | grep -o '[0-9]% packet loss' | cut -f1 -d%)
	if [ $lost -gt 0 ];then
		return 1
	fi
	pt=$(echo "$ping_resp" | tail -1 | awk '{print $4}' | cut -d '/' -f 2)
	if [ -n "$pt" -a "$pt" != "0" ];then
		echo "$pt,$1"
	fi
}

#$1:ip list
_ping_test(){
	pids=""
	for item in $1; do
		_get_ping_time "$item" &
		pids="$pids $!"
	done
	for job in $pids
	do
		wait $job
	done
}

#$1:domain,$2:ip,$3:download url
_download_speed(){
	dl_speed=$(_CURL --resolve $1:443:$2 -w %{speed_download} --connect-timeout 5 --max-time 5 -o /dev/null "$3")
	if [ -n "$dl_speed" -a "$dl_speed" != "0" ];then
		echo "$dl_speed,$2"
		dl_speed=$(printf "%.0f" $dl_speed)
		dl_speed=$(printf "%.0f" $((dl_speed/1024)) | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta')
		_log "%s: %s KB/s.\n" $2 $dl_speed
	fi
}

#$1:ip list,$2:url
_speed_test(){
	host=$(echo "$2" | awk -F'[/:]' '{print $4}')
	for item in $1; do
		_download_speed "$host" $item  "$2"
	done
}

#$1:result list
_get_res_ip(){
	ips=""
	for item in $1; do
		ip=$(echo "$item" | cut -d ',' -f 2)
		ips="$ips $ip"
	done
	echo "$ips" | sed -e "s/^[ ]*//"
}

#$1:result list
_fmt_speed(){
	data=""
	for item in $1; do
		dl_speed=$(echo "$item" | cut -d ',' -f 1)
		ip=$(echo "$item" | cut -d ',' -f 2)
		dl_speed=$(printf "%.0f" $dl_speed)
		dl_speed=$(printf "%.0f" $((dl_speed/1024)) | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta')
		str=$(printf "%s:%sKB/s\n" $ip $dl_speed)
		data="$data $str"
	done
	echo "$data" | sed -e "s/^[ ]*//"
}
#$1:ip v4/6
#$2:gen cf ip count
#$3:get N ping fast ip for test speed
#$4:get top N speed
#$5:url for test download
#$6:return type,0-only ip,1-speed,ip
_get_fast_ip(){
	ip_type=$1
	ping_c=$2
	dl_c=$3
	fast_c=$4
	ret_type=$5
	[ -n "$6" ] || ret_type=0
	_log "Generate random cloudflare %d ips...\n" $ping_c
	if [ $ip_type -eq 4 ];then
		ips_t=$(_gen_cf_ips $ping_c)
	else
		ips_t=$(_gen_cf_ipv6s $ping_c)
	fi
	if [ -z "$ips_t" ];then
		_log "Generate random cloudflare error, please check the network.\n"
		return 1
	fi

	_log "Ping testing these %d ips...\n" $ping_c
	res_ping=$(_ping_test "$ips_t")
	if [ -z "$res_ping" -o "$res_ping" = " " ];then
		_log "Ping test eror.\n"
		return 1
	fi
	fast=$(echo "$res_ping" | sort -n | head -$dl_c)

	_log "The fastest ip of ping test:\n[%s]\n" "$fast"
	ips=$(_get_res_ip "$fast")

	_log "Download speed testing these %d ips...\n" $dl_c
	res_speed=$(_speed_test "$ips" "$5")
	if [ -z "$res_speed" ];then
		_log "Download speed test eror.\n"
		return 1
	fi
	fast=$(echo "$res_speed" | sort -n -r | head -$fast_c)
	if [ "$ret_type" = "0" ];then
		ips=$(_get_res_ip "$fast")
		_log "Top %d fast ip:%s\n" $fast_c "$ips"
		echo -n "$ips"
	else
		echo -n "$fast"
	fi
}

#$1:url,$2:type 0-dns server,1-ip,$3:ip/dns server
_test_current_speed(){
	url=$1
	ips="$3"
	if [ "$2" != "1" ];then
		host=$(echo "${url}" | awk -F'[/:]' '{print $4}')
		if [ -z "$3" ];then
			ips=$(_get_dns "$host")
		else
			ips=$(_get_dns "$host" "$3")
		fi
	fi
	_log "test download use these ips:\n$ips"
	st=$(_speed_test "$ips" "$1")
}

_test_ipv6(){
	code=$(_CURL -6 -I --connect-timeout 5 -w %{http_code} -o /dev/null "$IPV6_TEST_URL")
	if [ "$code" = "200" ];then
		echo 1
	else
		echo 0
	fi
}

help()
{
   printf "Usage:\n"
   printf "$0 [-4/6] [-p <num>] [-d <num>] [-f <num>] [-c <command>]\n"
   printf "$0 [-t] [-n <dns server>] [-r <url>] [-a <ip address list>]\n"
   printf "\t-4/6 Get ipv4 or ipv6;\n"
   printf "\t-p Generate random IP addresses number for ping test;\n"
   printf "\t-d Set the number of IP addresses for the download test;\n"
   printf "\t-f Set the fastest number of IP addresses returned;\n"
   printf "\t-c Set the post execution command, Internal variable {{FAST_V4_IPS}} & {{FAST_V6_IPS}} can be used;\n"
   printf "\t-t Test current IP speed;\n"
   printf "\t-n Set dns server for test download speed;\n"
   printf "\t-a Set dns resolution ip address list for the host of url;\n"
   printf "\t-r Set url to test download speed;\n"
   printf "\t-h Print help.\n"
   exit 1 # Exit script after printing help
}
#main
while getopts "a:c:d:f:p:r:n:46th" opt
do
   case "$opt" in
   		4 ) ip_type=4 ;;
   		6 ) ip_type=6 ;;
   		a ) ip="$OPTARG" ;;
   		c ) post_cmd="$OPTARG" ;;
      d ) dl_c="$OPTARG" ;;
      f ) fast_c="$OPTARG" ;;
      p ) ping_c="$OPTARG" ;;
      r ) url="$OPTARG" ;;
      n ) dns="$OPTARG" ;;
      t ) tcs=1 ;;
      h | ? ) help ;;
   esac
done

[ -n "$ping_c" ] || ping_c=$DEFAULT_PING_COUNT
[ -n "$dl_c" ] || dl_c=$DEFAULT_DL_SPEED_COUNT
[ -n "$fast_c" ] || fast_c=$DEFAULT_FAST_COUNT
[ -n "$url" ] || url=$SPEED_TEST_URL

if [ "$tcs" = 1 ];then
	if [ -n "$ip" ];then
		_test_current_speed "$url" 1 "$ip"
	else
		_test_current_speed "$url" 0 "$dns"
	fi
	exit
fi
ipv6_enable=$(_test_ipv6)
if [ -n "$ip_type" ];then
	if [[ "$ip_type" = 6 ]] && [[ "$ipv6_enable" = "0" ]];then
		_log "IPv6 network test eror.\n"
		exit 1
	fi
	fast_data=$(_get_fast_ip $ip_type "$ping_c" "$dl_c" "$fast_c" "$url" 1)
	export fast_data_${ip_type}="$fast_data"
else
	fast_data_4=$(_get_fast_ip 4 "$ping_c" "$dl_c" "$fast_c" "$url" 1)
	fast_speed=$(_fmt_speed "$fast_data_4")
	if [ "$ipv6_enable" = "1" ];then
		fast_data_6=$(_get_fast_ip 6 "$ping_c" "$dl_c" "$fast_c" "$url" 1)
	fi
fi

echo "fast ipv4:[$(_fmt_speed "$fast_data_4")]"
echo "fast ipv6:[$(_fmt_speed "$fast_data_6")]"

if [ -n "$post_cmd" ];then
	fast_ips_4=$(_get_res_ip "$fast_data_4")
	fast_ips_6=$(_get_res_ip "$fast_data_6")
	post_cmd=$(echo "$post_cmd" | sed -e "s/{{FAST_V4_IPS}}/${fast_ips_4}/g" -e "s/{{FAST_V6_IPS}}/${fast_ips_6}/g")
	_log "exec cmd:${post_cmd}\n"
	eval "$post_cmd"
fi