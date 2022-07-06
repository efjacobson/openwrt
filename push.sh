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
cp -r etc .tmp
mv .tmp/rc.local.sh .tmp/rc.local
mv .tmp/rc.local.actual.sh .tmp/rc.local.actual

for i in `ls .tmp`; do
    sed -i 's/\r//' .tmp/"${i/\*/}" # replace CRLF with LF
done

chmod 644 .tmp/profile
scp -r .tmp/* root@192.168.1.1:/etc/
rm  -r .tmp

source $(pwd)/redact-passwords.sh

###########################################################################################

# find files with CRLF line endings
# grep -rIl -m 1 $'\r' etc/
