#!/bin/sh

if [[ `source get-redacted-count.sh` != 0 ]]; then
    if [ ! -f ".passwords" ]; then
        echo "passwords redacted and nothing to restore them from"
        sleep 3
        exit 1
    else
        source $(pwd)/restore-passwords.sh
    fi
fi

[ -d .tmp ] && rm  -r .tmp
mkdir .tmp
cp -r lib .tmp/lib
cp -r etc .tmp/etc
mv .tmp/etc/rc.local.sh .tmp/etc/rc.local
mv .tmp/etc/rc.local.actual.sh .tmp/etc/rc.local.actual

for i in `find .tmp -not -type d`; do
  sed -i 's/\r//' "$i" # replace CRLF with LF
done

chmod 644 .tmp/lib/netifd/netifd-wireless.sh
chmod 644 .tmp/etc/profile
chmod 644 .tmp/etc/hotplug.d/iface/99-vpn
chmod +x .tmp/etc/openvpn/cg/routes-vpn.sh

scp -r .tmp/* root@192.168.1.1:/

rm  -r .tmp

source $(pwd)/redact-passwords.sh

###########################################################################################

# find files with CRLF line endings
# grep -rIl -m 1 $'\r' etc/
