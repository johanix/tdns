#!/bin/sh
appversion=$1
appdate=$2
prog=$3

if [ "$prog" = "tdns-agent" ] || [ "$prog" = "tdns-server" ] || [ "$prog" = "music-sidecar" ]; then 
	echo generating version.go
	echo "package main" > version.go
	echo "const appVersion = \"$appversion\"" >> version.go
	echo "const appDate = \"$appdate\"" >> version.go
	echo "const appName = \"$prog\"" >> version.go
else
	echo not generating version.go
fi

