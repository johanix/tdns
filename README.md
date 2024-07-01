# tdns

tdns is a small authoritative nameserver written in Go to be used various
experiments and tests. It is intended to be really simple to understand
and modify as needed. The repo consists of three separate programs:

## tdnsd
A simple authoritative DNS nameserver with some special features. 
See **tdnsd/README.md**

## tdns-cli
A CLI tool to interact with **tdnsd** via a REST-ful API. See 
**tdns-cli/README.md**

## dog
A CLI tool that seems like a very simplistic cousin to
the much more powerful tool "dig", which is part of the BIND9
distribution from ISC. The primary raison d'etre for "dog" is that
it understands the experimental new record types **DSYNC** and **DELEG**.
