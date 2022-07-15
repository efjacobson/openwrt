#!/bin/sh

echo `cat root/etc/rc.local.actual.sh | grep -c "key='redacted'"`
