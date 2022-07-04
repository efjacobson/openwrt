# you need dnsmasq-full to use dnssec
# opkg update; cd /tmp/ && opkg download dnsmasq-full; opkg install ipset libnettle8 libnetfilter-conntrack3; opkg remove dnsmasq; opkg install dnsmasq-full --cache /tmp/; rm -f /tmp/dnsmasq-full*.ipk;
# from https://docs.openwrt.melmac.net/vpn-policy-routing/#how-to-install-dnsmasq-full

echo "begin /etc/rc.local"
echo ""

DRY_RUN=0
BUILD_DEV=0
BUILD_GUEST=0
IP_THIRD_OCTET=1

for opt in "$@"
  do
  case ${opt} in
    --dry-run)
      DRY_RUN=1
    ;;
    --build-dev)
      BUILD_DEV=1
    ;;
    --build-guest)
      BUILD_GUEST=1
    ;;
  esac
done

if [[ "$DRY_RUN" == 1 ]]; then
  echo "dry run"
  echo ""
fi

if [[ "$BUILD_DEV" == 1 ]]; then
  echo "with dev build"
  echo ""
fi

if [[ "$BUILD_GUEST" == 1 ]]; then
  echo "with guest build"
  echo ""
fi

log_execute() {
  local OIFS="$IFS"
  IFS=$'\n'

  echo "$1"
  echo ""
  for i in $1; do
    eval "$i"
  done
  echo "###########################################################################################"
  echo ""
  IFS=$OIFS
}

add_list_dns() {
  local interface="$1"
  set -- '1.1.1.1' '1.0.0.1' '8.8.8.8' '8.8.4.4'

  for i; do
    uci add_list network."$interface".dns="$i"
  done
}

add_list_icmp_type() {
  local rule="$1"
  shift

  for i in "$@"
  do
    uci add_list firewall."$rule".icmp_type="$i"
  done
}

clear_section() {
  local section="$1"
  OIFS="$IFS"
  IFS=$'\n'

  local results=`uci show "$section"`
  while [[ "$results" ]]; do
    for i in $results; do
      item="${i/$section./}"
      item=`echo "$item" | sed "s/[.=].\+//"`
      uci -q delete "$section"."$item"
    done
    results=`uci show "$section"`
  done

  IFS=$OIFS
}

get_next_device_count() {
  OIFS="$IFS"
  IFS=$'\n'

  local count=1;
  local pattern=""$1"-[0-9]+'$"
  for i in `uci show network`; do
    if [[ "$i" =~ "$pattern" ]]; then
    count=$((count+1))
    fi
  done

  IFS=$OIFS

  echo "$count"
}

end() {
  uci changes
  echo ""

  if [[ "$DRY_RUN" == 1 ]]; then
    echo "dry run"
  else
    uci commit
    wifi reload
    /etc/init.d/network restart
    /etc/init.d/firewall restart
    echo ""
    /etc/init.d/dnsmasq restart
  fi
  echo ""

  if [[ "$BUILD_DEV" == 1 ]]; then
    echo "with dev build"
    echo ""
  fi

  if [[ "$BUILD_GUEST" == 1 ]]; then
    echo "with guest build"
    echo ""
  fi

  echo "end /etc/rc.local"
  echo ""
}

clear_section "dhcp"
clear_section "firewall"
clear_section "network"
clear_section "wireless"

RADIO_DEVICES=`find / -type d -name '*.pci'`

PHY_0=`find /sys/devices/ -type d -name 'phy0'`
PHY_1=`find /sys/devices/ -type d -name 'phy1'`

RADIO_0_PATH="${PHY_0/\/sys\/devices\/platform\//}"
RADIO_0_PATH="${RADIO_0_PATH/\/ieee80211\/phy0/}"

RADIO_1_PATH="${PHY_1/\/sys\/devices\/platform\//}"
RADIO_1_PATH="${RADIO_1_PATH/\/ieee80211\/phy1/}"

###########################################################################################

cmd=`cat <<EOI
uci set wireless.radio0=wifi-device
uci set wireless.radio0.cell_density='0'
uci set wireless.radio0.channel='36'
uci set wireless.radio0.country='US'
uci set wireless.radio0.htmode='VHT80'
uci set wireless.radio0.hwmode='11a'
uci set wireless.radio0.path="$RADIO_0_PATH"
uci set wireless.radio0.type='mac80211'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci set wireless.radio1=wifi-device
uci set wireless.radio1.cell_density='0'
uci set wireless.radio1.channel='11'
uci set wireless.radio1.country='US'
uci set wireless.radio1.htmode='HT20'
uci set wireless.radio1.hwmode='11g'
uci set wireless.radio1.path="$RADIO_1_PATH"
uci set wireless.radio1.type='mac80211'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci set network.loopback=interface
uci set network.loopback.device='lo'
uci set network.loopback.ipaddr='127.0.0.1'
uci set network.loopback.netmask='255.0.0.0'
uci set network.loopback.proto='static'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci set network.globals=globals
uci set network.globals.ula_prefix='fd34:1494:66ce::/48'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add network device > /dev/null
uci set network.@device[-1].name='eth0'
uci set network.@device[-1].ipv6='0'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add network device > /dev/null
uci set network.@device[-1].name='eth0.2'
uci set network.@device[-1].ifname='eth0'
uci set network.@device[-1].ipv6='0'
uci set network.@device[-1].type='8021q'
uci set network.@device[-1].vid='2'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add network device > /dev/null
uci set network.@device[-1].name='eth1'
uci set network.@device[-1].ipv6='0'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add network device > /dev/null
uci set network.@device[-1].name='eth1.1'
uci set network.@device[-1].ifname='eth1'
uci set network.@device[-1].ipv6='0'
uci set network.@device[-1].type='8021q'
uci set network.@device[-1].vid='1'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add network switch > /dev/null
uci set network.@switch[-1]=switch
uci set network.@switch[-1].name='switch0'
uci set network.@switch[-1].enable_vlan='1'
uci set network.@switch[-1].reset='1'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add network switch_vlan > /dev/null
uci set network.@switch_vlan[-1]=switch_vlan
uci set network.@switch_vlan[-1].device='switch0'
uci set network.@switch_vlan[-1].ports='1 2 3 4 6t'
uci set network.@switch_vlan[-1].vlan='1'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add network switch_vlan > /dev/null
uci set network.@switch_vlan[-1]=switch_vlan
uci set network.@switch_vlan[-1].device='switch0'
uci set network.@switch_vlan[-1].ports='5 0t'
uci set network.@switch_vlan[-1].vlan='2'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add firewall defaults > /dev/null
uci set firewall.@defaults[-1].synflood_protect='1'
uci set firewall.@defaults[-1].input='ACCEPT'
uci set firewall.@defaults[-1].output='ACCEPT'
uci set firewall.@defaults[-1].forward='REJECT'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add firewall include > /dev/null
uci set firewall.@include[-1].path='/etc/firewall.user'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add dhcp dnsmasq > /dev/null
uci set dhcp.@dnsmasq[-1].authoritative='1'
uci set dhcp.@dnsmasq[-1].boguspriv='1'
uci set dhcp.@dnsmasq[-1].dnssec='1'
uci set dhcp.@dnsmasq[-1].domain='lan'
uci set dhcp.@dnsmasq[-1].domainneeded='1'
uci set dhcp.@dnsmasq[-1].ednspacket_max='1232'
uci set dhcp.@dnsmasq[-1].expandhosts='1'
uci set dhcp.@dnsmasq[-1].leasefile='/tmp/dhcp.leases'
uci set dhcp.@dnsmasq[-1].local='/lan/'
uci set dhcp.@dnsmasq[-1].localise_queries='1'
uci set dhcp.@dnsmasq[-1].localservice='1'
uci set dhcp.@dnsmasq[-1].nonwildcard='1'
uci set dhcp.@dnsmasq[-1].readethers='1'
uci set dhcp.@dnsmasq[-1].rebind_localhost='1'
uci set dhcp.@dnsmasq[-1].rebind_protection='1'
uci set dhcp.@dnsmasq[-1].resolvfile='/tmp/resolv.conf.d/resolv.conf.auto'
uci set dhcp.@dnsmasq[-1].strictorder='1'
EOI`
log_execute "$cmd"

# config dnsmasq
#         option authoritative    1
#         option boguspriv        1
#         option domain   'lan'
#         option domainneeded     1
#         option ednspacket_max   1232
#         option expandhosts      1
#         option filterwin2k      0  # enable for dial on demand
#         option leasefile        '/tmp/dhcp.leases'
#         option local    '/lan/'
#         option localise_queries 1
#         option localservice     1  # disable to allow DNS requests from non-local subnets
#         option nonegcache       0
#         option nonwildcard      1 # bind to & keep track of interfaces
#         option readethers       1
#         option rebind_localhost 1  # enable for RBL checking and similar services
#         option rebind_protection 1  # disable if upstream must serve RFC1918 addresses
#         option resolvfile       '/tmp/resolv.conf.d/resolv.conf.auto'
#         #list bogusnxdomain     '64.94.110.11'
#         #list interface         br-lan
#         #list notinterface      lo
#         #list rebind_domain example.lan  # whitelist RFC1918 responses for domains
#         #list server            '/mycompany.local/1.2.3.4'

cmd=`cat <<EOI
uci set dhcp.lan=dhcp
uci set dhcp.lan.interface='lan'
uci set dhcp.lan.leasetime='12h'
uci set dhcp.lan.limit='150'
# uci set dhcp.lan.ra='server'
uci set dhcp.lan.start='100'
EOI`
log_execute "$cmd"

# config dhcp lan
#         option interface        lan
#         option leasetime        12h
#         option limit    150
#         option start    100

cmd=`cat <<EOI
uci set dhcp.wan=dhcp
uci set dhcp.wan.interface='wan'
uci set dhcp.wan.ignore='1'
# uci set dhcp.wan.ra_flags='none'
EOI`
log_execute "$cmd"

# config dhcp wan
#         option ignore   1
#         option interface        wan

#cmd=`cat <<EOI
#uci set dhcp.odhcpd=odhcpd
#uci set dhcp.odhcpd.maindhcp='0'
#uci set dhcp.odhcpd.leasefile='/tmp/hosts/odhcpd'
#uci set dhcp.odhcpd.leasetrigger='/usr/sbin/odhcpd-update'
#uci set dhcp.odhcpd.logLevel='4'
#EOI`
#log_execute "$cmd"

###########################################################################################

cmd=`cat <<EOI
uci add network device > /dev/null
uci set network.@device[-1].name='lan'
uci set network.@device[-1].ipv6='0'
uci set network.@device[-1].ports='eth1.1'
uci set network.@device[-1].type='bridge'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci set network.lan=interface
uci set network.lan.device='lan'
uci set network.lan.ipaddr='192.168.$IP_THIRD_OCTET.1'
uci set network.lan.netmask='255.255.255.0'
uci set network.lan.proto='static'
add_list_dns "lan"
EOI`
log_execute "$cmd"

IP_THIRD_OCTET=$((IP_THIRD_OCTET+1))

cmd=`cat <<EOI
uci set network.wan=interface
uci set network.wan.device='eth0.2'
uci set network.wan.peerdns='0'
uci set network.wan.proto='dhcp'
uci set network.wan.type='bridge'
add_list_dns "wan"
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci set wireless.default_radio0=wifi-iface
uci set wireless.default_radio0.device='radio0'
uci set wireless.default_radio0.encryption='psk2'
uci set wireless.default_radio0.key='redacted'
uci set wireless.default_radio0.mode='ap'
uci set wireless.default_radio0.network='lan'
uci set wireless.default_radio0.ssid='openwrt-5.0'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add network device > /dev/null
uci set network.@device[-1].name='wlan0'
uci set network.@device[-1].ipv6='0'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci set wireless.default_radio1=wifi-iface
uci set wireless.default_radio1.device='radio1'
uci set wireless.default_radio1.encryption='psk2'
uci set wireless.default_radio1.key='redacted'
uci set wireless.default_radio1.mode='ap'
uci set wireless.default_radio1.network='lan'
uci set wireless.default_radio1.ssid='openwrt-2.4'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add network device > /dev/null
uci set network.@device[-1].name='wlan1'
uci set network.@device[-1].ipv6='0'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add firewall zone > /dev/null
uci set firewall.@zone[-1]=zone
uci set firewall.@zone[-1].name='lan'
uci set firewall.@zone[-1].network='lan'
uci set firewall.@zone[-1].input='ACCEPT'
uci set firewall.@zone[-1].output='ACCEPT'
uci set firewall.@zone[-1].forward='ACCEPT'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add firewall zone > /dev/null
uci set firewall.@zone[-1]=zone
uci set firewall.@zone[-1].name='wan'
uci set firewall.@zone[-1].masq='1'
uci set firewall.@zone[-1].mtu_fix='1'
uci set firewall.@zone[-1].network='wan'
uci set firewall.@zone[-1].input='REJECT'
uci set firewall.@zone[-1].output='ACCEPT'
uci set firewall.@zone[-1].forward='REJECT'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add firewall forwarding > /dev/null
uci set firewall.@forwarding[-1].dest='wan'
uci set firewall.@forwarding[-1].src='lan'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add firewall rule > /dev/null
uci set firewall.@rule[-1].name='Allow-DHCP-Renew'
uci set firewall.@rule[-1].dest_port='68'
uci set firewall.@rule[-1].family='ipv4'
uci set firewall.@rule[-1].proto='udp'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].target='ACCEPT'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add firewall rule > /dev/null
uci set firewall.@rule[-1].name='Allow-IGMP'
uci set firewall.@rule[-1].family='ipv4'
uci set firewall.@rule[-1].proto='igmp'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].target='ACCEPT'
EOI`
log_execute "$cmd"

#cmd=`cat <<EOI
#uci add firewall rule > /dev/null
#uci set firewall.@rule[-1].name='Allow-Ping'
#uci set firewall.@rule[-1].family='ipv4'
#uci set firewall.@rule[-1].icmp_type='echo-request'
#uci set firewall.@rule[-1].proto='icmp'
#uci set firewall.@rule[-1].src='wan'
#uci set firewall.@rule[-1].target='ACCEPT'
#EOI`
#log_execute "$cmd"

#cmd=`cat <<EOI
#uci add firewall rule > /dev/null
#uci set firewall.@rule[-1].name='Allow-DHCPv6'
#uci set firewall.@rule[-1].dest_ip='fc00::/6'
#uci set firewall.@rule[-1].dest_port='546'
#uci set firewall.@rule[-1].enabled='0'
#uci set firewall.@rule[-1].family='ipv6'
#uci set firewall.@rule[-1].proto='udp'
#uci set firewall.@rule[-1].src='wan'
#uci set firewall.@rule[-1].src_ip='fc00::/6'
#uci set firewall.@rule[-1].target='ACCEPT'
#EOI`
#log_execute "$cmd"

#cmd=`cat <<EOI
#uci add firewall rule > /dev/null
#uci set firewall.@rule[-1].name='Allow-MLD'
#uci set firewall.@rule[-1].enabled='0'
#uci set firewall.@rule[-1].family='ipv6'
#uci set firewall.@rule[-1].proto='icmp'
#uci set firewall.@rule[-1].src='wan'
#uci set firewall.@rule[-1].src_ip='fe80::/10'
#uci set firewall.@rule[-1].target='ACCEPT'
#add_list_icmp_type "@rule[-1]" '130/0' '131/0' '132/0' '143/0'
#EOI`
#log_execute "$cmd"

#cmd=`cat <<EOI
#uci add firewall rule > /dev/null
#uci set firewall.@rule[-1].name='Allow-ICMPv6-Input'
#uci set firewall.@rule[-1].enabled='0'
#uci set firewall.@rule[-1].family='ipv6'
#uci set firewall.@rule[-1].limit='1000/sec'
#uci set firewall.@rule[-1].proto='icmp'
#uci set firewall.@rule[-1].src='wan'
#uci set firewall.@rule[-1].target='ACCEPT'
#add_list_icmp_type "@rule[-1]" 'echo-request' 'echo-reply' 'destination-unreachable' 'packet-too-big' 'time-exceeded' 'bad-header' 'unknown-header-type' 'router-solicitation' 'neighbour-solicitation' 'router-advertisement' 'neighbour-advertisement'
#EOI`
#log_execute "$cmd"

#cmd=`cat <<EOI
#uci add firewall rule > /dev/null
#uci set firewall.@rule[-1].name='Allow-ICMPv6-Forward'
#uci set firewall.@rule[-1].dest='*'
#uci set firewall.@rule[-1].enabled='0'
#uci set firewall.@rule[-1].family='ipv6'
#uci set firewall.@rule[-1].limit='1000/sec'
#uci set firewall.@rule[-1].proto='icmp'
#uci set firewall.@rule[-1].src='wan'
#uci set firewall.@rule[-1].target='ACCEPT'
#add_list_icmp_type "@rule[-1]" 'echo-request' 'echo-reply' 'destination-unreachable' 'packet-too-big' 'time-exceeded' 'bad-header' 'unknown-header-type'
#EOI`
#log_execute "$cmd"

#cmd=`cat <<EOI
#uci add firewall rule > /dev/null
#uci set firewall.@rule[-1].name='Allow-IPSec-ESP'
#uci set firewall.@rule[-1].dest='lan'
#uci set firewall.@rule[-1].family='ipv4'
#uci set firewall.@rule[-1].proto='esp'
#uci set firewall.@rule[-1].src='wan'
#uci set firewall.@rule[-1].target='ACCEPT'
#EOI`
#log_execute "$cmd"

#cmd=`cat <<EOI
#uci add firewall rule > /dev/null
#uci set firewall.@rule[-1].name='Allow-ISAKMP'
#uci set firewall.@rule[-1].dest='lan'
#uci set firewall.@rule[-1].dest_port='500'
#uci set firewall.@rule[-1].family='ipv4'
#uci set firewall.@rule[-1].proto='udp'
#uci set firewall.@rule[-1].src='wan'
#uci set firewall.@rule[-1].target='ACCEPT'
#EOI`
#log_execute "$cmd"

###########################################################################################

if [ "$BUILD_GUEST" == 0 ] && [ "$BUILD_DEV" == 0 ]; then
  end
  exit 0
fi

echo "start building guest"
echo ""

cmd=`cat <<EOI
uci set wireless.guest_radio0=wifi-iface
uci set wireless.guest_radio0.device='radio0'
uci set wireless.guest_radio0.encryption='psk2'
uci set wireless.guest_radio0.key='redacted'
uci set wireless.guest_radio0.mode='ap'
uci set wireless.guest_radio0.network='lan'
uci set wireless.guest_radio0.ssid='openwrt-5.0-guest'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add network device > /dev/null
uci set network.@device[-1].name='wlan0-$(get_next_device_count "wlan0")'
uci set network.@device[-1].ipv6='0'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci set wireless.guest_radio1=wifi-iface
uci set wireless.guest_radio1.device='radio1'
uci set wireless.guest_radio1.encryption='psk2'
uci set wireless.guest_radio1.key='redacted'
uci set wireless.guest_radio1.mode='ap'
uci set wireless.guest_radio1.network='guest'
uci set wireless.guest_radio1.ssid='openwrt-2.4-guest'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add network device > /dev/null
uci set network.@device[-1].name='wlan1-$(get_next_device_count "wlan1")'
uci set network.@device[-1].ipv6='0'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci set network.guest=interface
uci set network.guest.ipaddr='192.168.$IP_THIRD_OCTET.1'
uci set network.guest.netmask='255.255.255.0'
uci set network.guest.proto='static'

add_list_dns "guest"
EOI`
log_execute "$cmd"

IP_THIRD_OCTET=$((IP_THIRD_OCTET+1))

cmd=`cat <<EOI
uci set dhcp.guest=dhcp
uci set dhcp.guest.interface='guest'
uci set dhcp.guest.leasetime='1h'
uci set dhcp.guest.limit='150'
uci set dhcp.guest.start='100'

# uci add_list dhcp.guest.ra_flags='none'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add firewall zone > /dev/null
uci set firewall.@zone[-1].name='guest'
uci set firewall.@zone[-1].input='REJECT'
uci set firewall.@zone[-1].output='ACCEPT'
uci set firewall.@zone[-1].forward='REJECT'
uci add_list firewall.@zone[-1].network='guest'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add firewall forwarding > /dev/null
uci set firewall.@forwarding[-1].src='guest'
uci set firewall.@forwarding[-1].dest='wan'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add firewall rule > /dev/null
uci set firewall.@rule[-1].name='Guest DNS'
uci set firewall.@rule[-1].dest_port='53'
uci set firewall.@rule[-1].family='ipv4'
uci set firewall.@rule[-1].src='guest'
uci set firewall.@rule[-1].target='ACCEPT'
uci add_list firewall.@rule[-1].proto='tcp'
uci add_list firewall.@rule[-1].proto='udp'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add firewall rule > /dev/null
uci set firewall.@rule[-1].name='Guest DHCP'
uci set firewall.@rule[-1].dest_port='67'
uci set firewall.@rule[-1].family='ipv4'
uci set firewall.@rule[-1].src='guest'
uci set firewall.@rule[-1].target='ACCEPT'
uci add_list firewall.@rule[-1].proto='udp'
EOI`
log_execute "$cmd"

###########################################################################################

if [ "$BUILD_DEV" == 0 ]; then
  end
  exit 0
fi

echo "start building dev"
echo ""

cmd=`cat <<EOI
uci add network device > /dev/null
uci set network.@device[-1].name='lan_1'

uci set network.@device[-1].ipv6='0'
uci set network.@device[-1].ports='eth1.1'
uci set network.@device[-1].type='bridge'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci set network.lan_1=interface
uci set network.lan_1.device='lan_1'
uci set network.lan_1.ipaddr='192.168.$IP_THIRD_OCTET.1'
uci set network.lan_1.netmask='255.255.255.0'
uci set network.lan_1.proto='static'
add_list_dns "lan_1"
EOI`
log_execute "$cmd"

IP_THIRD_OCTET=$((IP_THIRD_OCTET+1))

cmd=`cat <<EOI
uci set network.wan_1=interface
uci set network.wan_1.device='eth0.2'
uci set network.wan_1.peerdns='0'
uci set network.wan_1.proto='dhcp'
uci set network.wan_1.type='bridge'
add_list_dns "wan_1"
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci set wireless.default_radio01=wifi-iface
uci set wireless.default_radio01.device='radio0'

uci set wireless.default_radio01.encryption='psk2'
uci set wireless.default_radio01.key='redacted'
uci set wireless.default_radio01.mode='ap'
uci set wireless.default_radio01.network='lan_1'
uci set wireless.default_radio01.ssid='openwrt-5.0-dev'

###

uci add network device > /dev/null
uci set network.@device[-1].name='wlan0-$(get_next_device_count "wlan0")'

uci set network.@device[-1].ipv6='0'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci set wireless.default_radio11=wifi-iface
uci set wireless.default_radio11.device='radio1'

uci set wireless.default_radio11.encryption='psk2'
uci set wireless.default_radio11.key='redacted'
uci set wireless.default_radio11.mode='ap'
uci set wireless.default_radio11.network='lan_1'
uci set wireless.default_radio11.ssid='openwrt-2.4-dev'

###

uci add network device > /dev/null
uci set network.@device[-1].name='wlan1-$(get_next_device_count "wlan1")'

uci set network.@device[-1].ipv6='0'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci set firewall.lan_1=zone
uci set firewall.lan_1.name='lan_1'

uci set firewall.lan_1.network='lan_1'

uci set firewall.lan_1.input='ACCEPT'
uci set firewall.lan_1.output='ACCEPT'
uci set firewall.lan_1.forward='ACCEPT'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci set firewall.wan_1=zone
uci set firewall.wan_1.name='wan_1'

uci set firewall.wan_1.network='wan_1'

uci set firewall.wan_1.input='REJECT'
uci set firewall.wan_1.output='ACCEPT'
uci set firewall.wan_1.forward='REJECT'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci set firewall.wtf_forwarding=forwarding
uci set firewall.wtf_forwarding.dest='wan_1'
uci set firewall.wtf_forwarding.src='lan_1'
EOI`
log_execute "$cmd"

echo "end building dev"
echo ""

###########################################################################################

end

exit 0
