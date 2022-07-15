echo "begin /etc/rc.local"
echo ""

[ -f /lib/netifd/netifd-wireless.sh ] && chmod 644 /lib/netifd/netifd-wireless.sh
[ -f /etc/profile ] && chmod 644 /etc/profile
[ -f /etc/hotplug.d/iface/99-vpn ] && chmod 644 /etc/hotplug.d/iface/99-vpn
[ -f /etc/openvpn/vpn_0/vpn_0_routes.sh ] && chmod +x /etc/openvpn/vpn_0/vpn_0_routes.sh

# ( sleep 30 ; sh /etc/rc.local.actual --build-guest ) &

echo "end /etc/rc.local"
echo ""
