#!/bin/sh
appversion=$1
appdate=$2
prog=$3

echo "package main" > version.go
echo "const appVersion = \"$appversion\"" >> version.go
echo "const appDate = \"$appdate\"" >> version.go
echo "const appName = \"$prog\"" >> version.go
