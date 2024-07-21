#!/usr/bin/env sh
ps --pid $(pgrep anonycast) -L -o 'lwp ucmd' | grep deaddrop-worker | awk '{print $1}'
