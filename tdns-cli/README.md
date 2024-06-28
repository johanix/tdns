# tdns-cli

A simple CLI tool to interact with the TDNSD authoritative nameserver
via a REST-ful API.

**tdns-cli** has a substantial number of sub-commands to deal with different
features of **tdnsd**. The sub-commands are grouped under different prefixes:

- "tdns-cli zone ...": generate NSEC chain, sign zone, freeze|thaw, 
  reload, etc.

- "tdns-cli ddns ...": various commands to send DNS UPDATE messages.
