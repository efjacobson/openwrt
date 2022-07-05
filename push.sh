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

scp -r etc/* root@192.168.1.1:/etc/
