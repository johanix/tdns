# **tdns-reporter**

Description

**tdns-reporter** is a small, single-purpose service that only listens
for TSIG-signed NOTIFY messages with an EDNS(0) Reporter option attached.

The intent is to provide a reporting channel for multi provider DNS
errors and problems.

The tdns-cli tool has a new sub command, "report" which may be used to
test and demonstrate this functionality. Example:

tdns-cli report -z foffa.z2.axfr.net -S johani -D "no coffee"

Arguments are:
-z zonename
-S sender    name of sender (a corresponding TSIG key with name {sender}.key. must
		   exist in the tdns-cli.yaml config file).
--ede num    EDE code point to set
-D "details" additional text describing the problem






