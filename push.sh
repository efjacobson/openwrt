#!/bin/sh

if [[ `source get-redacted-count.sh` != 0 ]]; then
    echo "you didnt restore the passwords"
    exit 1
fi

cp etc/rc.local.sh etc/rc.local
scp etc/profile etc/rc.local root@192.168.1.1:/etc/
rm etc/rc.local