#!/bin/sh

echo `cat etc/rc.local.actual | grep -c "key='redacted'"`
