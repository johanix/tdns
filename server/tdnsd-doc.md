# Technical Documentation for TDNS

## Overview

TDNS is a small authoritative nameserver written in Go, designed for experiments and tests. The repository consists of three separate programs:

1. **tdnsd**: An authoritative DNS nameserver with extra features for child-to-parent synchronization.
2. **tdns-cli**: A CLI utility to interact with tdnsd.
3. **dog**: A simple DNS query tool similar to the well-known tool "dig".

## tdnsd

### Overview

**tdnsd** is the most complex component of the TDNS suite. It is a small authoritative DNS nameserver with support for various features, including child-to-parent synchronization, dynamic updates, and a built-in keystore and truststore.

### Features

- Load zones from text files on disk.
- Inbound and outbound NOTIFY support.
- AXFR support (no IXFR support yet).
- Respond to DNSSEC queries.
- Online signing of unsigned zones.
- Built-in REST API for management.
- Limited support for inbound SIG(0) signed dynamic updates.
- Support for experimental DSYNC and DELEG record types.
- Built-in keystore and truststore for DNSSEC and SIG(0) keys.

### Goroutines and Their Interactions

tdnsd uses several goroutines to handle different tasks concurrently. Below is a detailed description of each goroutine, their purpose, communication methods, and data structures used.

#### Main Goroutine

- **Purpose**: Initializes the server, sets up signal handling, and starts other goroutines.
- **Communication**: Uses channels to communicate with other goroutines.
- **Data Structures**: `Config`, `sync.WaitGroup`, `os.Signal`.

#### Updater Engine Goroutine

- **Purpose**: Handles update requests to the DNS database.
- **Communication**: Listens on the `updateq` channel for `UpdateRequest` messages.
- **Data Structures**: `UpdateRequest`, `sync.WaitGroup`, `chan struct{}`.

#### Scanner Engine Goroutine

- **Purpose**: Periodically scans zones for changes and updates.
- **Communication**: Uses a ticker to trigger periodic scans.
- **Data Structures**: `ScanRequest`, `ScanResponse`, `sync.WaitGroup`, `chan struct{}`.

#### Signal Handling Goroutine

- **Purpose**: Handles OS signals for graceful shutdown and configuration reload.
- **Communication**: Listens on the `exit` and `hupper` channels for signals.
- **Data Structures**: `os.Signal`, `sync.WaitGroup`.

### Goroutine Interaction Graph
dot
digraph G {
rankdir=LR;
node [shape=box];
Main [label="Main Goroutine"];
Updater [label="Updater Engine Goroutine"];
Scanner [label="Scanner Engine Goroutine"];
SignalHandler [label="Signal Handling Goroutine"];
Main -> Updater [label="Start"];
Main -> Scanner [label="Start"];
Main -> SignalHandler [label="Start"];
Updater -> Main [label="Update Complete"];
Scanner -> Main [label="Scan Complete"];
SignalHandler -> Main [label="Signal Received"];
}
