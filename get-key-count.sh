#!/bin/sh

key_count=0
echo `cat root/etc/rc.local.actual.sh | grep "\.key='"` | while IFS= read -r line; do
  if [[ "$line" == *"wireless"* ]]; then
    key_count=$((key_count+1))
  fi
done

echo "$key_count"
