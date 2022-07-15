#!/bin/sh

[ ! -f ".passwords" ] && return

while read -r line; do
  name=`echo "$line" | sed "s|='.*||"`
  name=""$name"='redacted'"
  sed -i "s|$name|$line|g" root/etc/rc.local.actual.sh
done < .passwords

rm .passwords
