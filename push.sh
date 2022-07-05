#!/bin/sh

if [[ `source get-redacted-count.sh` != 0 ]]; then
    if [ ! -f ".passwords" ]; then
        echo "passwords redacted and nothing to restore them from"
        exit 1
    else
        source $(pwd)/restore-passwords.sh
    fi
fi

for i in `ls etc`; do
    sed -i 's/\r//' etc/"${i/\*/}" # replace CRLF with LF
done

scp -r etc/* root@192.168.1.1:/etc/

source $(pwd)/redact-passwords.sh

###########################################################################################

# find files with CRLF line endings
# grep -rIl -m 1 $'\r' etc/
