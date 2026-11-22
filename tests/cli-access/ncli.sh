#!/bin/sh
# ncli.sh [cli] CONFIG ARGS...: run tdns-ncli (or, with "cli" first,
# tdns-cli) from the build under test with the rig's CLI config
# $RIG/ncli/CONFIG.yaml (or $RIG/CONFIG.yaml when CONFIG has a slash, as in
# home/x: the ordinary user's own files), then print "RC=<exit status>".
#
# Arguments are plain words: the suites call this through su and ssh, and
# nothing here needs quoting.
RIG=/var/tmp/cli-access
tool=tdns-ncli
[ "$1" = cli ] && { tool=tdns-cli; shift; }
case $1 in */*) cfg=$RIG/$1.yaml ;; *) cfg=$RIG/ncli/$1.yaml ;; esac
shift
cd "$RIG" || exit 1
"$RIG/bin/$tool" --config "$cfg" "$@" 2>&1 < /dev/null
echo "RC=$?"
