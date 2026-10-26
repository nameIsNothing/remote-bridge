#!/bin/sh
# Finder opens executable .command files in Terminal. If the USB filesystem
# drops executable bits, run: sh "/Volumes/<USB>/RemoteBridge/unix/Start.command"
set -eu
case $0 in
    /*) entry_path=$0 ;;
    *) entry_path=$PWD/$0 ;;
esac
entry_directory=$(CDPATH= cd -P "$(dirname "$entry_path")" && pwd)
exec /bin/sh "$entry_directory/start-unix.sh" "$@"
