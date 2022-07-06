#!/bin/sh

echo `cat etc/rc.local.actual.sh | grep -c "key='redacted'"`
