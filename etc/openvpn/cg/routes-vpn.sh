#!/usr/bin/env sh

table=vpn

if [ "$script_type" == "route-up" ]; then
  ip route add default via $route_vpn_gateway dev $dev table $table proto static
elif [ "$script_type" == "route-pre-down" ]; then
  ip route del default via $route_vpn_gateway dev $dev table $table proto static
fi
