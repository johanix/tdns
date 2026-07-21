#!/bin/sh
# make-version.sh [--if-changed] <appversion> <appdate> <prog>
#
# Writes version.go (appVersion/appDate/appName constants) for the
# versioned programs. With --if-changed, version.go is left untouched
# when it already records exactly <appversion>; it is (re)written when
# the file is missing or the version string differs (new commits, a
# branch switch, or a clean<->dirty transition all change the string,
# since it embeds `git describe --dirty`). This keeps `go build` a
# no-op on unchanged trees — an unconditional rewrite would refresh
# appDate and force a relink of every app on every make run.
ifchanged=no
if [ "$1" = "--if-changed" ]; then
    ifchanged=yes
    shift
fi

appversion=$1
appdate=$2
prog=$3

versioned_progs="tdns-agent tdns-auth tdns-combiner tdns-cli \
		 dog tdns-imr tdns-reporter tdns-scanner tdns-debug"

case " $versioned_progs " in
    *" $prog "*)
	if [ "$ifchanged" = yes ] && [ -f version.go ] &&
	   grep -qxF "const appVersion = \"${appversion}\"" version.go; then
	    exit 0
	fi
	echo generating version.go
	{
	echo "package main"
	echo "const appVersion = \"${appversion}\""
	echo "const appDate = \"${appdate}\""
	echo "const appName = \"${prog}\""
	} > version.go || {
	echo "Error: Failed to generate version.go" >&2
	exit 1
	}
	;;
    *)
	# Quiet under --if-changed: this runs on every build.
	if [ "$ifchanged" = no ]; then
	    echo not generating version.go, $prog is not a versioned program
	fi
	;;
esac
