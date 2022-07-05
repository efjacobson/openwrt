#!/bin/sh

if [ ! -f ".passwords" ]; then
  exit 1
fi

while read -r line; do
  NAME=`echo "$line" | sed "s|='.*||"`
  PATTERN=""$NAME"='redacted'"
  sed -i "s|$PATTERN|$line|g" etc/rc.local.actual
done < .passwords

rm .passwords
