#!/bin/sh
appversion=$1
appdate=$2
prog=$3

if [ "$prog" = "tdns-agent" ] || [ "$prog" = "tdns-server" ] || [ "$prog" = "music-sidecar" ]; then 
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
else
	echo not generating version.go
fi
