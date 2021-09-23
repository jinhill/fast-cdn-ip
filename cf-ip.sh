#! /bin/sh
#####################################################################
# Copyright (C) 2021 Jinhill
# https://github.com/jinhill/fast-cf-ip
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#####################################################################
VERSION="1.2.1"
USER_AGENT='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'
alias _CURL='curl -s -H "user-agent: $USER_AGENT" -H "accept: text/html;*/*"'
#SPEED_TEST_URL="https://cdn.yourdomain.com/download/100mb.zip"
SPEED_TEST_URL="https://tca.smokeset.net/dl/100mb.zip"
ANYCAST_SPEED_LOG=$(dirname "$0")/anycast_speed.log
CF_IPV4_URL="https://www.cloudflare.com/ips-v4"
#CF_IPV6_URL="https://www.cloudflare.com/ips-v6"
CF_IPV6_RANGE="2606:4700::/96 2606:4700:3031::/96 2606:4700:3032::/96 2606:4700:3033::/96"
IPV6_TEST_URL="https://ipv6-test.com"
DEFAULT_PING_COUNT=200
DEFAULT_DL_SPEED_COUNT=10
DEFAULT_FAST_COUNT=2
DEFAULT_DNS=""
DEFAULT_HOST="cdn.smoekset.net cdn6.smokeset.net"
DEFAULT_CMP_EXIST=1
DEFAULT_POST_CMD='/opt/sh/geos_dns.sh -bu "{{FAST_V4_IPS}}" "{{FAST_V6_IPS}}"'
_debug(){
	echo "$@" 1>&2
}

_log(){
	printf "$@" 1>&2
}
#$1:key,$2:value,$3:file
_reconfig(){
	k="$1"
	v=$(echo "$2" | sed 's/\//\\\//g')
	sed -i "/^$k=/s/=.*/=$v/" "$3"
}
#$1:string,$2:char, if $2 not set return array len,$ret:count
_count() {
	if [ -n "$2" ];then
  	echo "$1" | awk -F"$2" '{print NF-1}'
  else
   echo "$1" | wc -w
  fi
}

#$1:dommain,$2:dns server
_get_dns(){
	resolve_ips=""
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
	if [ -n "$2" ];then
		resolve_ips=$($resolve_cmd "$@")
	else
		resolve_ips=$($resolve_cmd "$1")
	fi
	echo "$resolve_ips" | tail -n +$head_line | grep -ioE '[a-fA-F0-9:.]{7,}$'
}

_test_ipv6(){
	code=$(_CURL -6 -I --connect-timeout 5 -w '%{http_code}' -o /dev/null "$IPV6_TEST_URL")
	if [ "$code" = "200" ];then
		echo 1
	else
		echo 0
	fi
}

hex2dec(){
	[ "$1" != "" ] && printf "%d" "$(( 0x$1 ))"
}

# expand an ipv6 address
expand_ipv6() {
	ip=$1

	# prepend 0 if we start with :
	echo "$ip" | grep -qs "^:" && ip="0${ip}"

	# expand ::
	if echo "$ip" | grep -qs "::" ; then
		colons=$(echo "$ip" | sed 's/[^:]//g')
		missing=$(echo ":::::::::" | sed "s/$colons//")
		expanded=$(echo "$missing" | sed 's/:/:0/g')
		ip=$(echo "$ip" | sed "s/::/$expanded/")
	fi

	blocks=$(echo "$ip" | grep -o "[0-9a-f]\+")
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
	echo "$1" | sed -e 's/\(:0\{1,4\}\)/:/g' -e 's/:\{3,\}/::/g'
}

#$1:char,$2:count
padding(){
	printf "%.s$1" $(seq $2)
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
	r_data=$(tr -dc "0123456789" < "/dev/urandom" | head -c$r_len)
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
				r_data=$(tr -dc "0123456789" < "/dev/urandom" | head -c$r_len)
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
	ip_range=$1
	ip_count=$2
	OLDIFS="$IFS"
	sub=$(echo "$ip_range" | cut -d '/' -f 1)
	sm=$(echo "$ip_range" | cut -d '/' -f 2)
	mask=$(( 1 << ( 32 - sm )))
	IFS="."
		set -- $sub
		ips=$((0x$(printf "%02x%02x%02x%02x\n" $1 $2 $3 $4)))
	IFS="$OLDIFS"
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
	max_mask=$((0xFFFF >> mask_part));
	min_mask=$((0xFFFF << (16 - mask_part)));
	max_part=$((ip_part_hex | max_mask))
	min_part=$((ip_part_hex & min_mask))
	padding_len=$(( (128 - part * 4 ) / 4))
	r_len=$(( 40 * ip_c))
	r_data=$(tr -dc "0123456789abcdef" < "/dev/urandom" | head -c$r_len)
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
			r_data=$(tr -dc "0123456789abcdef" < "/dev/urandom" | head -c$r_len)
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
	c=$1
	ip_range=$(_CURL "$CF_IPV4_URL")
	if [ -z "$ip_range" ];then
		_log "Get cloudflare ip range error.\n"
		return 1
	fi

	ip_r_c=$(echo "$ip_range" | awk 'END{print NR}')
	sub_c=$(( c/ip_r_c + 1))
	for item in $ip_range;do
		ips=$(_subnet "$item" $sub_c)
		printf "%s\n" "${ips}"
	done
}

#$1:ip count
_gen_cf_ipv6s(){
	c=$1
	range_c=$(_count "$CF_IPV6_RANGE")
	sub_c=$(( (c / range_c) + 1))
	for item in $CF_IPV6_RANGE;do
		ips=$(_subnet_v6 "$item" $sub_c)
		printf "%s\n" "${ips}"
	done
}
#$1:ip
_get_ping_time(){
	ping_resp=$(ping -c 5 -q $1)
	lost=$(echo "$ping_resp" | grep -o '[0-9]% packet loss' | cut -f1 -d%)
	if [ $lost -gt 0 ];then
		return 1
	fi
	pt=$(echo "$ping_resp" | tail -1 | awk '{print $4}' | cut -d '/' -f 2)
	if [ -n "$pt" ] && [ "$pt" != "0" ];then
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
	dl_speed=$(_CURL --resolve "$1":443:"$2" -w '%{speed_download}' --connect-timeout 5 --max-time 5 -o /dev/null "$3")
	if [ -n "$dl_speed" ] && [ "$dl_speed" != "0" ];then
		echo "$dl_speed,$2"
		dl_speed=$(printf "%.0f" $dl_speed)
		dl_speed=$(printf "%.0f" $((dl_speed/1024)) | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta')
		_log "%s: %s KB/s.\n" "$2" "$dl_speed"
	fi
}

#$1:ip list,$2:url
_speed_test(){
	host=$(echo "$2" | awk -F'[/:]' '{print $4}')
	for item in $1; do
		_download_speed "$host" "$item"  "$2"
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
#$1:4-ipv4,6-ipv6,else ipv4 & ipv6
_get_history_anycast_ips(){
	if [ ! -f "$ANYCAST_SPEED_LOG" ];then
		return 1
	fi
	sed -i "s/\r//g" "$ANYCAST_SPEED_LOG"
	case "$1" in
   		4 ) grep -ioE "[0-9.]{7,}$" "$ANYCAST_SPEED_LOG"
   				;;
   		6 ) grep -ioE "[a-fA-F0-9:]{7,}$" "$ANYCAST_SPEED_LOG"
   				;;
   		* ) grep -ioE "[a-fA-F0-9:.]{7,}$" "$ANYCAST_SPEED_LOG"
   				;;
  esac
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
	_log "Randomly generate %d Cloudflare ipv${ip_type} addresses...\n" $ping_c
	if [ $ip_type -eq 4 ];then
		ips_t=$(_gen_cf_ips $ping_c)
	else
		ips_t=$(_gen_cf_ipv6s $ping_c)
	fi
	if [ -z "$ips_t" ];then
		_log "Generate ip addresses error, please check the network.\n"
		return 1
	fi
	anycast_speed_ips=$(_get_history_anycast_ips $ip_type)
	if [ -n "$anycast_speed_ips" ];then
		asi_c=$(echo "$anycast_speed_ips" | wc -l)
		ping_c=$((ping_c + asi_c))
		ips_t=$(printf "%s\n%s\n" "$ips_t" "$anycast_speed_ips")
		_log "Add %d ips from the history to test ping.\n" $asi_c
	fi
	_log "Ping testing these %d ips...\n" $ping_c
	res_ping=$(_ping_test "$ips_t")
	if [ -z "$res_ping" ] || [ "$res_ping" = " " ];then
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
		echo "$ips"
	else
		echo "$fast"
	fi
	echo "$fast" >> "$ANYCAST_SPEED_LOG"
}

#$1:url,$2:ip/host list,$3:dns server
_test_current_speed(){
	url=$1
	ips=""
	if [ -n "$2" ];then
		for item in $2; do
			i_ip=$(echo "$item" | grep -ioE "[a-fA-F0-9:.]{7,}$")
			if [ -z "$i_ip" ]; then
				i_ip=$(_get_dns "$item" "$3")
			fi
			ips=$(printf "%s\n%s" "$ips" "$i_ip")
		done
	else
		host=$(echo "${url}" | awk -F'[/:]' '{print $4}')
		ips=$(_get_dns "$host" "$3")
	fi
	_log "Test download use these ips:\n$ips\n"
	st=$(_speed_test "$ips" "$1")
}

_cmp_exist_host(){
	[ "$cmp_exist" = "1" ] || return
	cs=$(_test_current_speed "$url" "$ip_host" "$dns")
	cs_4=$(echo "$cs" | grep -oE ".*,[0-9.]{7,}$")
	cs_6=$(echo "$cs" | grep -oE ".*,[a-fA-F0-9:]{7,}$")

	fast_res_4=$(printf "%s\n%s" "$fast_data_4" "$cs_4")
	fast_data_4=$(echo "$fast_res_4" | sort -n -r | head -$fast_c)
	
	fast_res_6=$(printf "%s\n%s" "$fast_data_6" "$cs_6")
	fast_data_6=$(echo "$fast_res_6" | sort -n -r | head -$fast_c)
}

help()
{
   printf "cf-ip.sh ver:%s\nUsage:\n" "$VERSION"
   printf "$0 [-4/6] [-p <num>] [-d <num>] [-f <num>] [-c] [-v] [-s <shell/command>]\n"
   printf "$0 -t [-n <dns server>] [-r <url>] [-a <ip address/real host list>]\n"
   printf "$0 --config [-c] [-p <num>] [-d <num>] [-f <num>] [-n <dns server>] [-r <url>] [-a <ip address/real host list>] [-s <shell/command>]\n"
   printf "\t-4/6 Get ipv4 or ipv6;\n"
   printf "\t-a Set dns resolution ip addresses or real host name list for the host of url;\n"
   printf "\t-c Compare the fastest speed with the existing ip speed;\n"
   printf "\t-d Set the number of ip addresses for the download test;\n"
   printf "\t-f Set the fastest number of ip addresses returned;\n"
   printf "\t-n Set dns server for test download speed;\n"
   printf "\t-p Generate random ip addresses number for ping test;\n"
   printf "\t-r Set url to test download speed;\n"
   printf "\t-s Set the post execution shell or command, internal variable {{FAST_V4_IPS}} & {{FAST_V6_IPS}} can be used;\n"
   printf "\t-t Test current ip speed;\n"
   printf "\t-v Version of this script;\n"
   printf "\t--config Set default parameters and persist;\n"
   printf "\t-h Print help.\n"
   exit 1
}
#main
while getopts "a:d:f:n:p:r:s:-:46chtv" opt
do
	case "$opt" in
		4 | 6 ) ip_type=${opt} ;;
		a ) ip_host="$OPTARG" ;;
		c ) cmp_exist=1 ;;
		d ) dl_c="$OPTARG" ;;
		f ) fast_c="$OPTARG" ;;
		n ) dns="$OPTARG" ;;
		p ) ping_c="$OPTARG" ;;
		r ) url="$OPTARG" ;;
		s ) post_cmd="$OPTARG" ;;
		t ) tcs=1 ;;
		v ) echo "$VERSION";exit ;;
		- ) case "${OPTARG}" in
					config )
						re_conf=1
					;;
					*)
						_log "Unknown option --%s\n" "${OPTARG}"
						help
					;;
				esac ;;
		h | ? ) help ;;
	esac
done
cmp_exist=${cmp_exist:-${DEFAULT_CMP_EXIST}}
dl_c=${dl_c:-${DEFAULT_DL_SPEED_COUNT}}
dns=${dns:-${DEFAULT_DNS}}
fast_c=${fast_c:-${DEFAULT_FAST_COUNT}}
ip_host=${ip_host:-${DEFAULT_HOST}}
ping_c=${ping_c:-${DEFAULT_PING_COUNT}}
post_cmd=${post_cmd:-${DEFAULT_POST_CMD}}
url=${url:-${SPEED_TEST_URL}}
if [ "$re_conf" = "1" ];then
	[ -z "$cmp_exist" ] || _reconfig "DEFAULT_CMP_EXIST" "${cmp_exist}" "$0"
	[ -z "$dl_c" ] || _reconfig "DEFAULT_DL_SPEED_COUNT" "${dl_c}" "$0"
	[ -z "$dns" ] || _reconfig "DEFAULT_DNS" "\"${dns}\"" "$0"
	[ -z "$fast_c" ] || _reconfig "DEFAULT_FAST_COUNT" "${fast_c}" "$0"
	[ -z "$ip_host" ] || _reconfig "DEFAULT_HOST" "\"${ip_host}\"" "$0"
	[ -z "$ping_c" ] || _reconfig "DEFAULT_PING_COUNT" "${ping_c}" "$0"
	[ -z "$post_cmd" ] || _reconfig "DEFAULT_POST_CMD" "'${post_cmd}'" "$0"
	[ -z "$url" ] || _reconfig "SPEED_TEST_URL" "\"${url}\"" "$0"
	exit
elif [ "$tcs" = 1 ];then
	if [ -n "$ip_host" ];then
		_test_current_speed "$url" "$ip_host" "$dns"
	else
		_test_current_speed "$url" "" "$dns"
	fi
	exit
fi
ipv6_enable=$(_test_ipv6)
if [ -n "$ip_type" ];then
	if [ "$ip_type" = 6 ] && [ "$ipv6_enable" = "0" ];then
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

_cmp_exist_host

echo "fast ipv4:[$(_fmt_speed "$fast_data_4")]"
echo "fast ipv6:[$(_fmt_speed "$fast_data_6")]"

if [ -n "$post_cmd" ];then
	fast_ips_4=$(_get_res_ip "$fast_data_4")
	fast_ips_6=$(_get_res_ip "$fast_data_6")
	post_cmd=$(echo "$post_cmd" | sed -e "s/{{FAST_V4_IPS}}/${fast_ips_4}/g" -e "s/{{FAST_V6_IPS}}/${fast_ips_6}/g")
	_log "exec cmd:${post_cmd}\n"
	eval "$post_cmd"
fi
