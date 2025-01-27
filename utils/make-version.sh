#!/bin/sh
appversion=$1
appdate=$2
prog=$3

versioned_progs="tdns-agent tdns-server music-sidecar"

# if [ "$prog" = "tdns-agent" ] || [ "$prog" = "tdns-server" ] || [ "$prog" = "music-sidecar" ]; then 
case " $versioned_progs " in
	*" $prog "*)
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
		echo not generating version.go, $prog is not a versioned program
		;;
esac
