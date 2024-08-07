# tdns-cli

A simple CLI tool to interact with the TDNSD authoritative nameserver
via a REST-ful API.

**tdns-cli** has a substantial number of sub-commands to deal with different
features of **tdnsd**. The sub-commands are grouped under different prefixes:

- "**tdns-cli zone**": generate NSEC chain, sign zone, freeze|thaw, 
  reload, etc.

- "**tdns-cli ddns**": various commands to send DNS UPDATE messages.

- "**tdns-cli update create**": a command to interactively compose a DNS UPDATE
  message before signing and sending it.

- "**tdns-cli keystore**": commands to manage the keystore (i.e. the
  repository of private/public key pairs used to SIG(0) sign UPDATE
  messages, DNSSEC sign a zone, etc). The commands include listing, 
  adding and deleting key pairs.

- "**tdns-cli truststore**": commands to manage the truststore (i.e. the
  repository of public keys for child zones, used to validate SIG(0)
  signed DNS UPDATE messages, DNSSEC signed CSYNC and CDS RRsets, etc. The
  commands include support for managing the **trust state** of each key
  (as opposed to whether the key is *known* or *validated*).

- "**tdns-cli notify**": commands to issue various types of generalized
  NOTIFY messages.

- "**tdns-cli dsync**": commands to examine DSYNC RRsets. (This is less
  relevant now that the **dog** tool is able to query for and present
  DSYNC RRsets natively).

I'm most likely forgetting some categories of commands. It is always 
possible to traverse the complete command hierarchy with the "-h" flag
as all possible sub-commands and valid flags are always listed.
