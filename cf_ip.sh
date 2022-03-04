#!/bin/sh
#######################################################
# Fast Cloudflare IP
# Copyright (C) 2021-2022 Jinhill
# Depend on: curl jq openssl
# Git repo: https://github.com/jinhill/fast-cf-ip
#######################################################
VERSION="1.2.6"
#SPEED_TEST_URL="https://cdn.yourdomain.com/download/100mb.zip"
SPEED_TEST_URL="https://speed.cloudflare.com/__down?bytes=100000000"
CF_SPEED_LOG=$(dirname "$0")/cf_speed.log
CF_IPV4_URL="https://www.cloudflare.com/ips-v4/"
#CF_IPV6_URL="https://www.cloudflare.com/ips-v6/"
CF_IPV6_RANGE="2606:4700::/96 2606:4700:58::/96 2606:4700:3031::/96 2606:4700:3032::/96 2606:4700:3033::/96 2803:f800:50::/96"
IPV6_TEST_URL="https://ip.gs"
DEFAULT_PING_COUNT=200
DEFAULT_DL_SPEED_COUNT=10
DEFAULT_FAST_COUNT=2
DEFAULT_DNS=""
DEFAULT_HOST="cdn.yourdomain.com cdn6.yourdomain.com"
DEFAULT_POST_CMD='/path/to/ddns_xxx.sh -4u -n "cdn.yourdomain.com" -v "{{FAST_V4_IPS}}";/path/to/ddns_xxx.sh -6u -n "cdn6.yourdomain.com" -v "{{FAST_V6_IPS}}"'
USER_AGENT='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'
alias _CURL='curl -s -H "user-agent: ${USER_AGENT}" -H "accept: text/html;*/*"'
#ERROR-0,WARN-1,INFO-2,DEBUG-3
LOG_LEVEL=2

#$1:level $2:string
log() {
  [ "$1" -le ${LOG_LEVEL} ] && printf "[%s]: %b\n" "$(date +'%Y-%m-%d %H:%M:%S')" "$2" >&2
}

#$1:key,$2:value,$3:file
reconfig() {
  k="$1"
  v=$(echo "$2" | sed 's/\//\\\//g')
  sed -i "/^$k=/s/=.*/=$v/" "$3"
}

#$1:string,$2:char, if $2 not set return array len,$ret:count
count() {
  if [ -n "$2" ]; then
    echo "$1" | awk -F"$2" '{print NF-1}'
  else
    echo "$1" | wc -w
  fi
}

#$1:dommain,$2:dns server
get_dns() {
  resolve_ips=""
  #need dnsutils
  resolve_cmd=nslookup
  head_line=3
  if [ -x "$(command -v host)" ]; then
    #debain
    resolve_cmd=host
    if [ -z "$2" ]; then
      head_line=1
    fi
  fi
  if [ -n "$2" ]; then
    resolve_ips=$(${resolve_cmd} "$1" "$2")
  else
    resolve_ips=$(${resolve_cmd} "$1")
  fi
  echo "${resolve_ips}" | tail -n +${head_line} | grep -ioE '[a-fA-F0-9:.]{7,}$'
}

test_ipv6() {
  code=$(_CURL -6 -s --connect-timeout 5 -w '%{http_code}' -o /dev/null "${IPV6_TEST_URL}")
  if [ "${code}" = "200" ]; then
    echo 1
  else
    echo 0
  fi
}

hex2dec() {
  [ "$1" != "" ] && printf "%d" "$((0x$1))"
}

# expand an ipv6 address
expand_ipv6() {
  ip=$1
  # prepend 0 if we start with :
  echo "${ip}" | grep -qs "^:" && ip="0${ip}"
  # expand ::
  if echo "${ip}" | grep -qs "::"; then
    colons=$(echo "${ip}" | sed 's/[^:]//g')
    missing=$(echo ":::::::::" | sed "s/$colons//")
    expanded=$(echo "${missing}" | sed 's/:/:0/g')
    ip=$(echo "${ip}" | sed "s/::/${expanded}/")
  fi
  blocks=$(echo "${ip}" | grep -o "[0-9a-f]\+")
  set ${blocks}
  printf "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n" \
    $(hex2dec "$1") \
    $(hex2dec "$2") \
    $(hex2dec "$3") \
    $(hex2dec "$4") \
    $(hex2dec "$5") \
    $(hex2dec "$6") \
    $(hex2dec "$7") \
    $(hex2dec "$8")
}

compress_ipv6() {
  echo "$1" | sed -e 's/\(:0\{1,4\}\)/:/g' -e 's/:\{3,\}/::/g'
}

#$1:char,$2:count
padding() {
  printf "%.s$1" $(seq $2)
}

fmt_ipv6() {
  echo "$1" | sed -e 's/.\{4\}/&:/g' -e 's/:$//'
}

#$1:count,$2:min,$3:max
gen_rand() {
  min=$2
  max=$3
  c=0
  no_repeat_rand=""
  rnd_len=$(($1 * 10))
  rnd_data=$(tr -dc "0123456789" <"/dev/urandom" | head -c${rnd_len})
  rnd_pos=1
  rnd_end=8
  while [ $c -lt $1 ]; do
    r=0
    while [ $r -eq 0 ]; do
      #get rand from ram
      rand=$(echo "${rnd_data}" | cut -b ${rnd_pos}-${rnd_end})
      rnd_pos=$((rnd_pos + 8))
      rnd_end=$((rnd_end + 8))
      if [ ${rnd_end} -ge ${rnd_len} ]; then
        rnd_data=$(tr -dc "0123456789" <"/dev/urandom" | head -c${rnd_len})
        rnd_pos=1
        rnd_end=8
      fi
      rand=$(echo "${rand}" | sed 's/^0*//')
      num=$(((rand % (max - min + 1)) + min))
      echo "${no_repeat_rand}" | grep -w "${num}" >/dev/null 2>&1
      r=$?
    done
    no_repeat_rand="${no_repeat_rand} ${num}"
    c=$((c + 1))
  done
  echo "${no_repeat_rand}"
}

#$1:ip/mask,$2:ip count
subnet() {
  ip_range=$1
  ip_cnt=$2
  OLDIFS="$IFS"
  sub=$(echo "${ip_range}" | cut -d '/' -f 1)
  sm=$(echo "${ip_range}" | cut -d '/' -f 2)
  mask=$((1 << (32 - sm)))
  IFS="."
  set -- ${sub}
  ips=$((0x$(printf "%02x%02x%02x%02x\n" $1 $2 $3 $4)))
  IFS="$OLDIFS"
  rand=$(gen_rand ${ip_cnt} 1 ${mask})
  for item in ${rand}; do
    val=$((ips | item))
    printf "%d.%d.%d.%d\n" \
      $(((val >> 24) & 255)) \
      $(((val >> 16) & 255)) \
      $(((val >> 8) & 255)) \
      $(((val) & 255))
  done
}

#$1:ipv6/mask,$2:ip count
subnet_v6() {
  ip_cnt=$2
  subnet=$(echo "$1" | cut -d '/' -f 1)
  prefix=$(echo "$1" | cut -d '/' -f 2)
  subnet=$(expand_ipv6 "${subnet}")
  ip_full=$(echo "${subnet}" | sed "s/://g")
  pos=$((prefix * 4 / 16))
  if [ ${pos} -gt 0 ]; then
    ip_head=$(echo "${ip_full}" | cut -b -${pos})
  fi
  part=$((pos + 4))
  pos=$((pos + 1))
  ip_part=$(echo "${ip_full}" | cut -b ${pos}-${part})
  ip_part_hex=$((0x${ip_part}))
  mask_part=$((prefix % 16))
  max_mask=$((0xFFFF >> mask_part))
  min_mask=$((0xFFFF << (16 - mask_part)))
  max_part=$((ip_part_hex | max_mask))
  min_part=$((ip_part_hex & min_mask))
  padding_len=$(((128 - part * 4) / 4))
  rnd_len=$((40 * ip_cnt))
  rnd_data=$(tr -dc "0123456789abcdef" <"/dev/urandom" | head -c${rnd_len})
  rnd_pos=0
  rnd_end=0
  c=0
  while [ $c -lt ${ip_cnt} ]; do
    #get rand from ram
    rnd_pos=$((rnd_end + 1))
    rnd_end=$((rnd_pos + 4))
    rand=$(echo "${rnd_data}" | cut -b ${rnd_pos}-${rnd_end})
    rnd_pos=$((rnd_end + 1))
    rnd_end=$((rnd_pos + padding_len - 1))
    if [ ${rnd_end} -ge ${rnd_len} ]; then
      rnd_data=$(tr -dc "0123456789abcdef" <"/dev/urandom" | head -c${rnd_len})
      rnd_pos=1
      rnd_end=${padding_len}
    fi
    rand_hex=$((0x$rand))
    rand_part=$(((rand_hex % (max_part - min_part + 1)) + min_part))
    rand_padding=$(echo "${rnd_data}" | cut -b ${rnd_pos}-${rnd_end})
    ip=$(printf "%s%04x%s\n" "${ip_head}" ${rand_part} "${rand_padding}")
    ip=$(fmt_ipv6 "${ip}")
    compress_ipv6 "${ip}"
    c=$((c + 1))
  done
}

#$1:ip count
gen_cf_ips() {
  c=$1
  ip_rngs=$(_CURL "${CF_IPV4_URL}")
  if [ -z "${ip_rngs}" ]; then
    log 0 "Get cloudflare ip range error."
    return 1
  fi

  rng_cnt=$(count "${ip_rngs}")
  sub_cnt=$((c / rng_cnt + 1))
  for item in ${ip_rngs}; do
    ips=$(subnet "${item}" ${sub_cnt})
    printf "%s\n" "${ips}"
  done
}

#$1:ip count
gen_cf_ipv6s() {
  c=$1
  rng_cnt=$(count "${CF_IPV6_RANGE}")
  sub_cnt=$(((c / rng_cnt) + 1))
  for item in ${CF_IPV6_RANGE}; do
    ips=$(subnet_v6 "${item}" ${sub_cnt})
    printf "%s\n" "${ips}"
  done
}

#$1:ip
get_ping_time() {
  ping_resp=$(ping -c 5 -q $1)
  lost=$(echo "${ping_resp}" | grep -o '[0-9]% packet loss' | cut -f1 -d%)
  if [ $lost -gt 0 ]; then
    return 1
  fi
  pt=$(echo "${ping_resp}" | tail -1 | awk '{print $4}' | cut -d '/' -f 2)
  if [ -n "${pt}" ] && [ "${pt}" != "0" ]; then
    echo "${pt},$1"
  fi
}

#$1:ip list
ping_test() {
  pids=""
  for item in $1; do
    get_ping_time "${item}" &
    pids="${pids} $!"
  done
  for job in ${pids}; do
    wait $job
  done
}

#$1:domain,$2:ip,$3:download url
download_speed() {
  dl_speed=$(_CURL --resolve "$1":443:"$2" -w '%{speed_download}' --connect-timeout 5 --max-time 5 -o /dev/null "$3")
  if [ -n "${dl_speed}" ] && [ "${dl_speed}" != "0" ]; then
    echo "${dl_speed},$2"
    log 2 "$2: $(fmt_speed ${dl_speed})."
  fi
}

#$1:ip list,$2:url
speed_test() {
  host=$(echo "$2" | awk -F'[/:]' '{print $4}')
  for item in $1; do
    download_speed "${host}" "${item}" "$2"
  done
}

#$1:result list
get_res_ip() {
  ips=""
  for item in $1; do
    ip=$(echo "${item}" | cut -d ',' -f 2)
    ips="${ips} ${ip}"
  done
  echo "${ips}" | sed -e "s/^[ ]*//"
}

#$1:result list
fmt_speed() {
  data=""
  for item in $1; do
    if echo "${item}" | grep -q ","; then
      speed=$(echo "${item}" | cut -d ',' -f 1)
      ip=$(echo "${item}" | cut -d ',' -f 2)
      ip_str="${ip}:"
    else
      speed="${item}"
      ip_str=""
    fi
    dl_speed=$(printf "%.0f" $((speed / 1024)) | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta')
    str=$(printf "%s%s KB/s\n" ${ip_str} ${dl_speed})
    data="${data} ${str}"
  done
  echo "${data}" | sed -e "s/^[ ]*//"
}

#$1:4-ipv4,6-ipv6,else ipv4 & ipv6
get_history_ips() {
  if [ ! -f "${CF_SPEED_LOG}" ]; then
    return 1
  fi
  sed -i "s/\r//g" "${CF_SPEED_LOG}"
  case "$1" in
  4)
    grep -ioE "[0-9.]{7,}$" "${CF_SPEED_LOG}"
    ;;
  6)
    grep -ioE "[a-f0-9:]{7,}$" "${CF_SPEED_LOG}"
    ;;
  *)
    grep -ioE "[a-f0-9:.]{7,}$" "${CF_SPEED_LOG}"
    ;;
  esac
}

#$1:fast ip with speed
add_history_ips() {
  [ -z "$1" ] && return 1
  ips=$(get_res_ip "$1")
  if [ -f "${CF_SPEED_LOG}" ]; then
    ips_e=$(echo "${ips}" | sed -e ':a; ;$!ba;s/ /\\|/g')
    sed -i "/${ips_e}/d" "${CF_SPEED_LOG}"
  fi
  echo "$1" >>"${CF_SPEED_LOG}"
}

#$1:ip type 4/6,$2:The Nth fastest ip from history log
get_history_speed() {
  if [ ! -f "${CF_SPEED_LOG}" ]; then
    echo "0"
    return
  fi
  n=$2
  regex="[0-9]*,[0-9.]{7,}$"
  [ "$1" = "6" ] && regex="[0-9]*,[a-f0-9:]{7,}$"
  speed_log=$(grep -ioE "${regex}" "${CF_SPEED_LOG}")
  if [ -z "${n}" ]; then
    nl=$(echo "${speed_log}" | wc -l)
    n=$((nl / 3))
    [ "${n}" -lt 5 ] && n="${nl}"
  fi
  speed=$(echo "${speed_log}" | sort -nr | sed -n "${n}p" | cut -d ',' -f 1)
  echo "${speed:-0}"
}

#$1:ip v4/6
#$2:gen cf ip count
#$3:get N ping fast ip for test speed
#$4:get top N speed
#$5:url for test download
#$6:return type,0-only ip,1-speed,ip
get_fast_ip() {
  ip_type=$1
  ping_cnt=$2
  dl_cnt=$3
  fast_cnt=$4
  ret_type=$5
  [ -n "$6" ] || ret_type=0
  log 2 "Randomly generate ${ping_cnt} Cloudflare ipv${ip_type} addresses..."
  if [ ${ip_type} -eq 4 ]; then
    ips_t=$(gen_cf_ips ${ping_cnt})
  else
    ips_t=$(gen_cf_ipv6s ${ping_cnt})
  fi
  if [ -z "${ips_t}" ]; then
    log 0 "Generate ip addresses error, please check the network."
    return 1
  fi
  cf_speed_ips=$(get_history_ips ${ip_type})
  if [ -n "${cf_speed_ips}" ]; then
    asi_c=$(echo "${cf_speed_ips}" | wc -l)
    ping_cnt=$((ping_cnt + asi_c))
    ips_t=$(printf "%s\n%s\n" "${ips_t}" "${cf_speed_ips}")
    log 2 "Add ${asi_c} ips from the history to test ping."
  fi
  log 2 "Ping testing these ${ping_cnt} ips..."
  res_ping=$(ping_test "${ips_t}")
  if [ -z "${res_ping}" ] || [ "${res_ping}" = " " ]; then
    log 0 "Ping test eror."
    return 1
  fi
  fast=$(echo "${res_ping}" | sort -n | head -${dl_cnt})

  log 2 "The fastest ip of ping test:\n[${fast}]"
  ips=$(get_res_ip "${fast}")

  log 2 "Download speed testing these ${dl_cnt} ips..."
  res_speed=$(speed_test "${ips}" "$5")
  if [ -z "${res_speed}" ]; then
    log 0 "Download speed test eror."
    return 1
  fi
  fast=$(echo "${res_speed}" | sort -n -r | head -${fast_cnt})
  if [ "${ret_type}" = "0" ]; then
    ips=$(get_res_ip "${fast}")
    log 2 "Top ${fast_cnt} fast ip:${ips}"
    echo "${ips}"
  else
    echo "${fast}"
  fi
}

#$1:url,$2:ip/host list,$3:dns server
test_current_speed() {
  url=$1
  ips=""
  if [ -n "$2" ]; then
    for item in $2; do
      i_ip=$(echo "${item}" | grep -ioE "[a-fA-F0-9:.]{7,}$")
      if [ -z "${i_ip}" ]; then
        i_ip=$(get_dns "${item}" "$3")
      fi
      ips=$(printf "%s\n%s" "${ips}" "${i_ip}")
    done
  else
    host=$(echo "${url}" | awk -F'[/:]' '{print $4}')
    ips=$(get_dns "${host}" "$3")
  fi
  log 2 "Test download use these ips:${ips}"
  st=$(speed_test "${ips}" "$1")
  echo "${st}" | sort -nr
}

help() {
  printf "%s ver:%s\nUsage:\n" "$0" "${VERSION}"
  printf "%s [-4/6] [-p <num>] [-d <num>] [-f <num>] [-c] [-v] [-s <shell/command>]\n" "$0"
  printf "%s -t [-n <dns server>] [-r <url>] [-a <ip address/real host list>]\n" "$0"
  printf "%s --config [-c] [-p <num>] [-d <num>] [-f <num>] [-n <dns server>] [-r <url>] [-a <ip address/real host list>] [-s <shell/command>]\n" "$0"
  printf "\t-4/6 Get ipv4 or ipv6;\n"
  printf "\t-a Set dns resolution ip addresses or real host name list for the host of url;\n"
  printf "\t-c Check the current speed to determine whether the IP needs to be replaced;\n"
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

main() {
  while getopts "a:d:f:n:p:r:s:-:46chtv" opt; do
    case "$opt" in
    4 | 6) ip_type=${opt} ;;
    a) real_addr="$OPTARG" ;;
    c) check=1 ;;
    d) dl_cnt="$OPTARG" ;;
    f) fast_cnt="$OPTARG" ;;
    n) dns="$OPTARG" ;;
    p) ping_cnt="$OPTARG" ;;
    r) url="$OPTARG" ;;
    s) post_cmd="$OPTARG" ;;
    t) tcs=1 ;;
    v)
      echo "$VERSION"
      exit
      ;;
    -) case "${OPTARG}" in
      config)
        re_conf=1
        ;;
      *)
        log 0 "Unknown option --${OPTARG}"
        help
        ;;
      esac ;;
    h | ?) help ;;
    esac
  done
  dl_cnt=${dl_cnt:-${DEFAULT_DL_SPEED_COUNT}}
  dns=${dns:-${DEFAULT_DNS}}
  fast_cnt=${fast_cnt:-${DEFAULT_FAST_COUNT}}
  real_addr=${real_addr:-${DEFAULT_HOST}}
  ping_cnt=${ping_cnt:-${DEFAULT_PING_COUNT}}
  post_cmd=${post_cmd:-${DEFAULT_POST_CMD}}
  url=${url:-${SPEED_TEST_URL}}

  h4_m_speed=$(get_history_speed 4)
  h6_m_speed=$(get_history_speed 6)
  log 2 "ipv4 median speed:$(fmt_speed ${h4_m_speed:-0}),ipv6 median speed:$(fmt_speed ${h6_m_speed:-0})"

  if [ "$re_conf" = "1" ]; then
    [ -z "${cmp_exist}" ] || reconfig "DEFAULT_CMP_EXIST" "${cmp_exist}" "$0"
    [ -z "${dl_cnt}" ] || reconfig "DEFAULT_DL_SPEED_COUNT" "${dl_cnt}" "$0"
    [ -z "${dns}" ] || reconfig "DEFAULT_DNS" "\"${dns}\"" "$0"
    [ -z "${fast_cnt}" ] || reconfig "DEFAULT_FAST_COUNT" "${fast_cnt}" "$0"
    [ -z "${real_addr}" ] || reconfig "DEFAULT_HOST" "\"${real_addr}\"" "$0"
    [ -z "${ping_cnt}" ] || reconfig "DEFAULT_PING_COUNT" "${ping_cnt}" "$0"
    [ -z "${post_cmd}" ] || reconfig "DEFAULT_POST_CMD" "'${post_cmd}'" "$0"
    [ -z "${url}" ] || reconfig "SPEED_TEST_URL" "\"${url}\"" "$0"
    exit
  elif [ "${tcs}" = 1 ] || [ "${check}" = 1 ]; then
    if [ -n "${real_addr}" ]; then
      cur_speed=$(test_current_speed "${url}" "${real_addr}" "${dns}")
    else
      cur_speed=$(test_current_speed "${url}" "" "${dns}")
    fi
    [ -z "${cur_speed}" ] || [ "${check}" = 0 ] && exit
    fast_cur_speed=$(echo "${cur_speed}" | head -1 | cut -d ',' -f 1)
    log 2 "fast current speed:$(fmt_speed ${fast_cur_speed:-0})"
    # Either ipv4 or ipv6 is fast
    #[ "${fast_cur_speed:-0}" -gt "${h4_m_speed:-0}" ] || [ "${fast_cur_speed:-0}" -gt "${h6_m_speed:-0}" ] && exit
    [ "${fast_cur_speed:-0}" -gt "${h4_m_speed:-0}" ] && exit
  fi

  ipv6_enable=$(test_ipv6)
  c=0
  t10_speed=0
  while [ $c -lt 3 ]; do
    if [ -n "${ip_type}" ]; then
      if [ "${ip_type}" = 6 ] && [ "${ipv6_enable}" = "0" ]; then
        log 0 "IPv6 network test eror."
        exit 1
      fi
      fast_data=$(get_fast_ip ${ip_type} "${ping_cnt}" "${dl_cnt}" "${fast_cnt}" "${url}" 1)
      export fast_data_${ip_type}="${fast_data}"
      fs=$(echo "${fast_data}" | sort -nr | head -1 | cut -d ',' -f 1)
      eval "t10_speed=\$h${ip_type}_t10_speed"
      if [ "${fs:-0}" -gt "${t10_speed:-0}" ]; then
        break
      fi
    else
      fast_data_4=$(get_fast_ip 4 "${ping_cnt}" "${dl_cnt}" "${fast_cnt}" "${url}" 1)
      fast_speed=$(fmt_speed "${fast_data_4}")
      if [ "${ipv6_enable}" = "1" ]; then
        fast_data_6=$(get_fast_ip 6 "${ping_cnt}" "${dl_cnt}" "${fast_cnt}" "${url}" 1)
      fi
      fs4=$(echo "${fast_data_4}" | sort -nr | head -1 | cut -d ',' -f 1)
      fs6=$(echo "${fast_data_6}" | sort -nr | head -1 | cut -d ',' -f 1)
      [ "${fs4:-0}" -lt "${h4_m_speed:-0}" ] && ip_type=4
      [ "${fs6:-0}" -lt "${h6_m_speed:-0}" ] && ip_type=$((ip_type + 6))
      if [ -z "${ip_type}" ]; then
        break
      elif [ "${ip_type}" = "10" ]; then
        ip_type=""
      fi
    fi
    c=$((c + 1))
    log 2 "No fast ip${ip_type} found this time, wait 30 seconds to retry."
    sleep 30
  done
  if [ $c -ge 3 ]; then
    log 1 "We tried 3 times and still can't find the fastest IP. Please try again later."
    exit
  fi
  add_history_ips "${fast_data_4}"
  add_history_ips "${fast_data_6}"
  echo "fast ipv4:[$(fmt_speed "${fast_data_4}")]"
  echo "fast ipv6:[$(fmt_speed "${fast_data_6}")]"

  if [ -n "${post_cmd}" ]; then
    fast_ips_4=$(get_res_ip "${fast_data_4}")
    fast_ips_6=$(get_res_ip "${fast_data_6}")
    post_cmd=$(echo "${post_cmd}" | sed -e "s/{{FAST_V4_IPS}}/${fast_ips_4}/g" -e "s/{{FAST_V6_IPS}}/${fast_ips_6}/g")
    log 2 "exec cmd:${post_cmd}"
    eval "${post_cmd}"
  fi
}

main "$@"
