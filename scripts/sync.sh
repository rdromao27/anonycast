#!/usr/bin/env sh

# Send from the current directory to the remote host
if [ -z "$HOST" ]; then
	HOST="dicluster"
fi

for host in $HOST ; do
    rsync --exclude target/ --exclude '*.json' --exclude output/ --exclude .git/ -avzp . $host:./anonycast/ || exit 1
    rsync -avzp ./target/x86_64-unknown-linux-musl/release/anonycast $host:./anonycast/bin/ || exit 1
done

# Send from the remote host to the current directory
#for host in dicluster ; do
#    rsync --exclude target/debug --exclude 'target/release/*/*' --exclude 'target/release/*.d' --exclude 'target/release/*.rlib' --exclude output/ --exclude .git/ -avzp $host:./anonycast/ .
#done
