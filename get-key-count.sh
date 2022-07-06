#!/bin/sh

# echo `cat etc/rc.local.actual.sh | grep -c "key='"`

[ -f .tmp ] && rm .tmp
touch .tmp

KEYS=`cat etc/rc.local.actual.sh | grep "\.key='"`
echo "$KEYS" > .tmp

key_count=0

comment_start="# "
while IFS= read -r line; do
  if [[ "$line" == *"wireless"* ]]; then
    key_count=$((key_count+1))
  fi
done < .tmp

rm .tmp

echo "$key_count"
