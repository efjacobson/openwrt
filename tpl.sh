#!/usr/bin/bash

tpl_src="$1"
shift

tpl_dest="$1"
shift

tpl_dest_dir=$(dirname $tpl_dest)
[[ "$tpl_dest_dir" != "." ]] && [[ ! -d "$tpl_dest_dir" ]] && mkdir -p "$tpl_dest_dir"
cp "$tpl_src" "$tpl_dest"

for opt in "$@"; do
  value="${opt#*=}"
  key=${opt/"=$value"/}
  key="tpl_${key/--/}"
  sed -i "s/{{ $key }}/$value/g" "$tpl_dest"
done
