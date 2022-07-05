#!/bin/sh

if [[ `source $(pwd)/get-redacted-count.sh` != 0 ]]; then
    echo "passwords already redacted"
    exit 1
fi

[ -f .passwords ] && rm .passwords
touch .passwords

[ -f .tmp ] && rm .tmp
touch .tmp

KEYS=`cat etc/rc.local.actual | grep -U ".key='"`
echo "$KEYS" > .tmp

while IFS= read -r line; do
  KEY="${line/uci set wireless./}"
  echo "$KEY" >> .passwords
done < .tmp

rm .tmp

sed -i "s|key='.*'|key='redacted'|g" etc/rc.local.actual
