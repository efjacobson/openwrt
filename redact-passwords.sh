#!/bin/sh

[ -f ".passwords" ] && return

echo "$(cat root/etc/rc.local.actual.sh | grep "\.key='")" | while IFS= read -r line; do
  if [[ "$line" == *"wireless"* ]]; then
    key="${line/uci set wireless./}"
    key="${key/"# "/}" # for comments all janky like
    echo "$key" >> .passwords
  fi
done

while IFS= read -r line; do
  in="$line"
  arr_in=(${in//=/ })
  sed -i "s|key=${arr_in[1]}|key='redacted'|g" root/etc/rc.local.actual.sh
done < .passwords
