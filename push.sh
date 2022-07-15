#!/usr/bin/bash

if [[ $(./get-redacted-count.sh) != 0 ]]; then
    if [ ! -f ".passwords" ]; then
        echo "passwords redacted and nothing to restore them from"
        sleep 3
        exit 1
    else
        source $(pwd)/restore.sh
    fi
fi

[ -d .tmp ] && rm -r .tmp
cp -r root .tmp
mv .tmp/etc/rc.local.sh .tmp/etc/rc.local
mv .tmp/etc/rc.local.actual.sh .tmp/etc/rc.local.actual

num_vpns=$(ls root/etc/openvpn | wc -l)
num_vpns=$((num_vpns-1))
for i in $(seq 0 $num_vpns); do
  vpn="vpn_$i"
  ./tpl.sh "tpl/etc/openvpn/vpn/routes.sh" ".tmp/etc/openvpn/$vpn/$(echo "$vpn")_routes.sh" --table="$vpn"
  chmod +x ".tmp/etc/openvpn/$vpn/$(echo "$vpn")_routes.sh"

  ./tpl.sh "tpl/etc/hotplug.d/iface/99" ".tmp/etc/hotplug.d/iface/99_$vpn" --table="$vpn"
  chmod 644 ".tmp/etc/hotplug.d/iface/99_$vpn"

  idx=0
  while read -r line; do
    if [[ "$idx" == "$i" ]]; then
      ./tpl.sh "tpl/etc/openvpn/vpn/ovpn" ".tmp/etc/openvpn/$vpn/$vpn.ovpn" \
        --idx="$i" \
        --vpn="$vpn" \
        --remote="$line"
    fi
    idx=$((idx+1))
  done < .vpn_remotes

cat << EOF >> .tmp/etc/iproute2/rt_tables
$((i+3)) $vpn
EOF

done

for i in `find .tmp -not -type d`; do
  sed -i 's/\r//' "$i" # replace CRLF with LF
done

chmod 644 .tmp/lib/netifd/netifd-wireless.sh
chmod 644 .tmp/etc/profile

scp -r .tmp/* root@192.168.1.1:/

rm  -r .tmp

source $(pwd)/redact.sh

###########################################################################################

# find files with CRLF line endings
# grep -rIl -m 1 $'\r' /
