#!/bin/sh

if [[ `source $(pwd)/get-redacted-count.sh` != 0 ]]; then
    echo "passwords already redacted"
    sleep 3
    exit 1
fi

[ -f .passwords ] && rm .passwords
touch .passwords

[ -f .tmp ] && rm .tmp
touch .tmp

KEYS=`cat etc/rc.local.actual | grep "\.key='"`
echo "$KEYS" > .tmp

comment_start="# "
while IFS= read -r line; do
  if [[ "$line" == *"wireless"* ]]; then
    KEY="${line/uci set wireless./}"
    KEY="${KEY/"$comment_start"/}"
    echo "$KEY" >> .passwords
  fi
done < .tmp

rm .tmp

while IFS= read -r line; do
  in="$line"
  arr_in=(${in//=/ })
  sed -i "s|key=${arr_in[1]}|key='redacted'|g" etc/rc.local.actual
done < .passwords
