# IMPORTANT
# - the first time openvpn-openssl is installed these files (may) need to be merged: /etc/config/openvpn /etc/config/openvpn-opkg


# you need dnsmasq-full to use dnssec (hold on this until vpn working correctly)
# opkg update; cd /tmp/ && opkg download dnsmasq-full; opkg install ipset libnettle8 libnetfilter-conntrack3; opkg remove dnsmasq; opkg install dnsmasq-full --cache /tmp/; rm -f /tmp/dnsmasq-full*.ipk;
# from https://docs.openwrt.melmac.net/vpn-policy-routing/#how-to-install-dnsmasq-full

# todo: consider json or something similar
# todo: and envtpl
# todo: figure out why network is deleting and recreating 2x (maybe try a sleep)
# todo: look into dhcp ra_flags
#   - https://github.com/openwrt/openwrt/blob/openwrt-21.02/package/network/services/odhcpd/files/odhcpd.defaults#L49-L50
#   - https://datatracker.ietf.org/doc/html/rfc4861#section-4.2
# todo: name interfaces after their mac addresses https://openwrt.org/docs/guide-user/base-system/hotplug#rename_interfaces_by_mac_address
# todo: see about using vpn dns
# todo: save existing config and if after all this jazz it is unchanged, dont need to reboot
# todo: see if swapping the vlan the pc is connected to will put the pc on vpn connection
# todo: put etc and lib in a root dir
# todo: https support

# todo: figure out the logic they use to auto apply the phy path. syslog says:
# Wed Jul  6 08:24:03 2022 daemon.notice netifd: radio1 (1567): WARNING: Variable 'data' does not exist or is not an array/object
# Wed Jul  6 08:24:03 2022 daemon.notice netifd: radio1 (1567): Bug: PHY is undefined for device 'radio1'
# Wed Jul  6 08:24:03 2022 daemon.notice netifd: radio0 (1579): WARNING: Variable 'data' does not exist or is not an array/object
# Wed Jul  6 08:24:03 2022 daemon.notice netifd: radio0 (1579): Bug: PHY is undefined for device 'radio0'

# R7800 switch ports
#
# CPU (eth0) 0
# CPU (eth1) 6
# LAN 1      4 - vpn
# LAN 2      3
# LAN 3      2
# LAN 4      1
# WAN        5

echo "begin /etc/rc.local.actual"
echo ""

install_packages() {
  local _did_update=0

  set -- 'diffutils' 'openvpn-openssl' 'luci-app-openvpn' 'ip-tiny'

  for i; do
    if [[ "$( opkg list-installed | grep "^$i - " )" == "" ]]; then
      if [[ "_did_update" == 0 ]]; then
        opkg update
        _did_update=1
      fi
      opkg install "$i"
    fi
  done
}

install_packages

dry_run=0
build_guest=0
build_vpn=0

ip_third_octet=1

for opt in "$@"
  do
  case ${opt} in
    --dry-run)
      dry_run=1
    ;;
    --build-guest)
      build_guest=1
    ;;
    --build-vpn)
      build_vpn=1
    ;;
  esac
done

if [[ "$dry_run" == 1 ]]; then
  echo "dry run"
  echo ""
fi

if [[ "$build_guest" == 1 ]]; then
  echo "with guest build"
  echo ""
fi

if [[ "$build_vpn" == 1 ]]; then
  echo "with vpn build"
  echo ""
fi

log_execute() {
  local OIFS="$IFS"
  IFS=$'\n'

  for i in $1; do
    echo "$i"
    eval "$i"
  done
  echo ""
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

  local cleared=""

  local results=`uci -X show $section`
  while [[ "$results" ]]; do
    for i in $results; do
      item="${i/$section./}"
      item=`echo "$item" | sed "s/[.=].\+//"`
      item="$section.$item"

      if [[ "$cleared" != *"$item"* ]]; then
        uci -q delete "$item"
        cleared="$item|$cleared"
      fi
    done
    sleep 1
    results=`uci -X show $section`
  done

  IFS=$OIFS
}

uci revert dhcp
uci revert firewall
uci revert network
uci revert wireless
uci revert openvpn

clear_section "dhcp"
clear_section "firewall"
clear_section "network"
clear_section "openvpn"
clear_section "wireless"

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

  if [[ "$dry_run" == 1 ]]; then
    echo "dry run"
  else
    uci commit
    wifi reload
    /etc/init.d/network restart
    /etc/init.d/firewall restart
    echo ""
    /etc/init.d/dnsmasq restart
    /etc/init.d/openvpn restart
  fi
  echo ""

  if [[ "$build_guest" == 1 ]]; then
    echo "with guest build"
    echo ""
  fi

  if [[ "$build_vpn" == 1 ]]; then
    echo "with vpn build"
    echo ""
  fi

  echo "end /etc/rc.local.actual"
  echo ""
}

phy_0=`find /sys/devices/ -type d -name 'phy0'`
phy_1=`find /sys/devices/ -type d -name 'phy1'`

radio_0_path="${phy_0/\/sys\/devices\/platform\//}"
radio_0_path="${radio_0_path/\/ieee80211\/phy0/}"

radio_1_path="${phy_1/\/sys\/devices\/platform\//}"
radio_1_path="${radio_1_path/\/ieee80211\/phy1/}"

###########################################################################################

cmd=`cat <<EOI
uci set wireless.radio0=wifi-device
uci set wireless.radio0.cell_density='0'
uci set wireless.radio0.channel='auto'
uci set wireless.radio0.country='US'
uci set wireless.radio0.htmode='VHT80'
uci set wireless.radio0.hwmode='11a'
uci set wireless.radio0.path="$radio_0_path"
uci set wireless.radio0.type='mac80211'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci set wireless.radio1=wifi-device
uci set wireless.radio1.cell_density='0'
uci set wireless.radio1.channel='auto'
uci set wireless.radio1.country='US'
uci set wireless.radio1.htmode='HT20'
uci set wireless.radio1.hwmode='11g'
uci set wireless.radio1.path="$radio_1_path"
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
uci set network.@device[-1].name='eth1'
uci set network.@device[-1].ipv6='0'
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
uci add network device > /dev/null
uci set network.@device[-1].name='lan'
uci set network.@device[-1].ipv6='0'
# uci set network.@device[-1].ports='eth1.1' # might be wrong
uci set network.@device[-1].type='bridge'
uci add_list network.@device[-1].ports='eth1.1'
uci add_list network.@device[-1].ports='eth1.1'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci set network.lan=interface
uci set network.lan.device='lan'
uci set network.lan.ipaddr='192.168.$ip_third_octet.1'
uci set network.lan.netmask='255.255.255.0'
uci set network.lan.proto='static'
add_list_dns "lan"
EOI`
log_execute "$cmd"

ip_third_octet=$((ip_third_octet+1))

cmd=`cat <<EOI
uci add network switch_vlan > /dev/null
uci set network.@switch_vlan[-1]=switch_vlan
uci set network.@switch_vlan[-1].description='LAN'
uci set network.@switch_vlan[-1].device='switch0'
uci set network.@switch_vlan[-1].vid='1'
uci set network.@switch_vlan[-1].vlan='1'
uci set network.@switch_vlan[-1].ports='6t 3 2 1'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add network device > /dev/null
# uci set network.@device[-1].name='eth1.1'
uci set network.@device[-1].name='eth1.1'
uci set network.@device[-1].type='8021q'
uci set network.@device[-1].ifname='eth1'
uci set network.@device[-1].vid='1'
uci set network.@device[-1].ipv6='0'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add network switch_vlan > /dev/null
uci set network.@switch_vlan[-1]=switch_vlan
uci set network.@switch_vlan[-1].description='WAN'
uci set network.@switch_vlan[-1].device='switch0'
uci set network.@switch_vlan[-1].ports='0t 5'
uci set network.@switch_vlan[-1].vid='2'
uci set network.@switch_vlan[-1].vlan='2'
EOI`
log_execute "$cmd"

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
uci add network device > /dev/null
uci set network.@device[-1].name='eth0.2'
uci set network.@device[-1].ifname='eth0'
uci set network.@device[-1].ipv6='0'
uci set network.@device[-1].type='8021q'
uci set network.@device[-1].vid='2'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add firewall defaults > /dev/null
uci set firewall.@defaults[-1].disable_ipv6='1'
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
# uci set dhcp.@dnsmasq[-1].dnssec='1' # removed (hold on this until vpn working correctly)
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

cmd=`cat <<EOI
uci set dhcp.lan=dhcp
uci set dhcp.lan.interface='lan'
uci set dhcp.lan.leasetime='12h'
uci set dhcp.lan.limit='150'
uci set dhcp.lan.start='100'

uci add_list dhcp.lan.ra_flags='none'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci set dhcp.wan=dhcp
uci set dhcp.wan.interface='wan'
uci set dhcp.wan.ignore='1'
EOI`
log_execute "$cmd"

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
uci set firewall.@rule[-1].name='Allow-DHCP-Renew'O
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

if [ "$build_guest" == 0 ] && [ "$build_vpn" == 0 ]; then
  end
  exit 0
fi

cmd=`cat <<EOI
uci add network switch_vlan > /dev/null
uci set network.@switch_vlan[-1].device='switch0'
uci set network.@switch_vlan[-1].vlan='3'
uci set network.@switch_vlan[-1].ports='6t 4'
uci set network.@switch_vlan[-1].vid='3'
uci set network.@switch_vlan[-1].description='VPN'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add network device > /dev/null
uci set network.@device[-1].name='eth1.3'
uci set network.@device[-1].ipv6='0'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add network device > /dev/null
uci set network.@device[-1].name='bridge-vpn'
uci set network.@device[-1].ipv6='0'
uci set network.@device[-1].type='bridge'
uci add_list network.@device[-1].ports='eth1.3'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci set network.vpn=interface
uci set network.vpn.device='bridge-vpn'
uci set network.vpn.type='bridge'
uci set network.vpn.ipaddr='192.168.3.1'
uci set network.vpn.netmask='255.255.255.0'
uci set network.vpn.proto='static'
uci set network.vpn.delegate='0'

add_list_dns "vpn"
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci set wireless.vpn_radio0=wifi-iface
uci set wireless.vpn_radio0.device='radio0'
uci set wireless.vpn_radio0.encryption='psk2'
uci set wireless.vpn_radio0.key='redacted'
uci set wireless.vpn_radio0.mode='ap'
uci set wireless.vpn_radio0.ssid='openwrt-5.0-vpn'
uci set wireless.vpn_radio0.network='vpn'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add network device > /dev/null
uci set network.@device[-1].name='wlan0-$(get_next_device_count "wlan0")'
uci set network.@device[-1].ipv6='0'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci set wireless.vpn_radio1=wifi-iface
uci set wireless.vpn_radio1.device='radio1'
uci set wireless.vpn_radio1.encryption='psk2'
uci set wireless.vpn_radio1.key='redacted'
uci set wireless.vpn_radio1.mode='ap'
uci set wireless.vpn_radio1.ssid='openwrt-2.4-vpn'
uci set wireless.vpn_radio1.network='vpn'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add network device > /dev/null
uci set network.@device[-1].name='wlan1-$(get_next_device_count "wlan1")'
uci set network.@device[-1].ipv6='0'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci set dhcp.vpn=dhcp
uci set dhcp.vpn.interface='vpn'
uci set dhcp.vpn.start='100'
uci set dhcp.vpn.limit='150'
uci set dhcp.vpn.leasetime='12h'
uci add_list dhcp.vpn.dhcp_option='6,1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4' # seems fishy
uci add_list dhcp.vpn.ra_flags='none'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci set openvpn.sample_server=openvpn
uci set openvpn.sample_server.port='1194'
uci set openvpn.sample_server.proto='udp'
uci set openvpn.sample_server.dev='tun'
uci set openvpn.sample_server.ca='/etc/openvpn/ca.crt'
uci set openvpn.sample_server.cert='/etc/openvpn/server.crt'
uci set openvpn.sample_server.key='/etc/openvpn/server.key'
uci set openvpn.sample_server.dh='/etc/openvpn/dh2048.pem'
uci set openvpn.sample_server.server='10.8.0.0 255.255.255.0'
uci set openvpn.sample_server.ifconfig_pool_persist='/tmp/ipp.txt'
uci set openvpn.sample_server.keepalive='10 120'
uci set openvpn.sample_server.persist_key='1'
uci set openvpn.sample_server.persist_tun='1'
uci set openvpn.sample_server.user='nobody'
uci set openvpn.sample_server.status='/tmp/openvpn-status.log'
uci set openvpn.sample_server.verb='3'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci set openvpn.sample_client=openvpn
uci set openvpn.sample_client.client='1'
uci set openvpn.sample_client.dev='tun'
uci set openvpn.sample_client.proto='udp'
uci set openvpn.sample_client.resolv_retry='infinite'
uci set openvpn.sample_client.nobind='1'
uci set openvpn.sample_client.persist_key='1'
uci set openvpn.sample_client.persist_tun='1'
uci set openvpn.sample_client.user='nobody'
uci set openvpn.sample_client.ca='/etc/openvpn/ca.crt'
uci set openvpn.sample_client.cert='/etc/openvpn/client.crt'
uci set openvpn.sample_client.key='/etc/openvpn/client.key'
uci set openvpn.sample_client.verb='3'

uci add_list openvpn.sample_client.remote='my_server_1 1194'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci set openvpn.vpn_0=openvpn
uci set openvpn.vpn_0.config='/etc/openvpn/vpn_0/vpn_0.ovpn'
uci set openvpn.vpn_0.enabled='1'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add network device > /dev/null
uci set network.@device[-1].name='tun0'
uci set network.@device[-1].ipv6='0'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci set network.wan_vpn=interface
uci set network.wan_vpn.device='tun0'
uci set network.wan_vpn.proto='none'
uci set network.wan_vpn.delegate='0'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add firewall zone > /dev/null
uci set firewall.@zone[-1].name='wan_vpn'
uci set firewall.@zone[-1].input='REJECT'
uci set firewall.@zone[-1].output='ACCEPT'
uci set firewall.@zone[-1].forward='REJECT'
uci set firewall.@zone[-1].masq='1'
uci set firewall.@zone[-1].mtu_fix='1'
uci add_list firewall.@zone[-1].network='wan_vpn'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add firewall zone > /dev/null
uci set firewall.@zone[-1].name='vpn'
uci set firewall.@zone[-1].input='REJECT'
uci set firewall.@zone[-1].output='ACCEPT'
uci set firewall.@zone[-1].forward='REJECT'
uci add_list firewall.@zone[-1].network='vpn'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add firewall forwarding > /dev/null
uci set firewall.@forwarding[-1].src='vpn'
uci set firewall.@forwarding[-1].dest='wan_vpn'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add firewall rule > /dev/null
uci set firewall.@rule[-1].name='Allow-vpn-Input-DHCPv4'
uci set firewall.@rule[-1].family='ipv4'
uci set firewall.@rule[-1].src='vpn'
uci set firewall.@rule[-1].src_port='68'
uci set firewall.@rule[-1].target='ACCEPT'
uci set firewall.@rule[-1].dest_port='67'

uci add_list firewall.@rule[-1].proto='udp'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add firewall rule > /dev/null
uci set firewall.@rule[-1].name='vpn DNS'
uci set firewall.@rule[-1].dest_port='53'
uci set firewall.@rule[-1].family='ipv4'
uci set firewall.@rule[-1].src='vpn'
uci set firewall.@rule[-1].target='ACCEPT'

uci add_list firewall.@rule[-1].proto='tcp'
uci add_list firewall.@rule[-1].proto='udp'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci add firewall rule > /dev/null
uci set firewall.@rule[-1].name='vpn DHCP'
uci set firewall.@rule[-1].dest_port='67'
uci set firewall.@rule[-1].family='ipv4'
uci set firewall.@rule[-1].src='vpn'
uci set firewall.@rule[-1].target='ACCEPT'

uci add_list firewall.@rule[-1].proto='udp'
EOI`
log_execute "$cmd"

###########################################################################################

if [[ "$build_guest" == 0 ]]; then
  end
  exit 0
fi

echo "start building guest"
echo ""

cmd=`cat <<EOI
uci add firewall rule > /dev/null
uci set firewall.@rule[-1].name='Allow-Guest-Input-DHCPv4'
uci set firewall.@rule[-1].family='ipv4'
uci add_list firewall.@rule[-1].proto='udp'
uci set firewall.@rule[-1].src='guest'
uci set firewall.@rule[-1].src_port='68'
uci set firewall.@rule[-1].target='ACCEPT'
uci set firewall.@rule[-1].dest_port='67'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci set wireless.guest_radio0=wifi-iface
uci set wireless.guest_radio0.device='radio0'
uci set wireless.guest_radio0.encryption='psk2'
uci set wireless.guest_radio0.key='redacted'
uci set wireless.guest_radio0.mode='ap'
uci set wireless.guest_radio0.network='guest'
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
uci set network.guest.ipaddr='192.168.$ip_third_octet.1'
uci set network.guest.netmask='255.255.255.0'
uci set network.guest.proto='static'

add_list_dns "guest"
EOI`
log_execute "$cmd"

ip_third_octet=$((ip_third_octet+1))

cmd=`cat <<EOI
uci add network device > /dev/null
# uci set network.@device[-1].name='eth1.3'
uci set network.@device[-1].name='eth1.3'
uci set network.@device[-1].type='8021q'
uci set network.@device[-1].ifname='eth1'
uci set network.@device[-1].vid='3'
uci set network.@device[-1].ipv6='0'
EOI`
log_execute "$cmd"

cmd=`cat <<EOI
uci set dhcp.guest=dhcp
uci set dhcp.guest.interface='guest'
uci set dhcp.guest.leasetime='1h'
uci set dhcp.guest.limit='150'
uci set dhcp.guest.start='100'

uci add_list dhcp.guest.ra_flags='none'
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

end
