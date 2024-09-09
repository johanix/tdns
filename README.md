# tdns

tdns is a small authoritative nameserver written in Go to be used various
experiments and tests. It used to be intended to be really simple to understand
and modify as needed. Now the traditional authoritative nameserver part is still
almost trivial, but it has sprouted a bunch of additional functionality on the side.

The repo consists of four separate programs:

## tdns-server
A simple authoritative DNS nameserver with some special features. 
See **server/README.md**

## tdns-cli
A CLI tool to interact with **tdns-server** via a REST-ful API. See 
**cli/README.md**

## dog
A CLI tool that seems like a very simplistic cousin to
the much more powerful tool "dig", which is part of the BIND9
distribution from ISC. The primary raison d'etre for "dog" is that
it understands the experimental new record types **DSYNC** and **DELEG**.

## tdns-agent
A version of **tdns-server** that must be configured as a secondary, downstream
of whatever is in use as the primary. The point with **tdns-agent** is to enable 
a zone to safely use the new synchronisation mechanisms without any requirement
to change the existing zone generation and publication setup. See **agent/README.md**.