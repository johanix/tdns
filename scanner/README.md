# **tdns-scanner**

## Description

**tdns-scanner** is a service that accepts scanning requests via a REST API. 
Requests list one or more zones and one or more things to lookup and compare
to possible existing data. Typical data to lookup include child CDS and CSYNC
records (CDS, CSYNC) and DNSKEY records. It analyzes CSYNC records according to
RFC 7477 to detect and process delegation changes in child zones.

The scanner receives scan requests via an API endpoint or internal channels,
processes them, and can send RFC 9567 error reports when certain conditions are
met.

## Functionality

The scanner performs the following operations:

1. **CSYNC Analysis**: When scanning a zone for CSYNC records, it:
   - Queries the child zone's CSYNC record over TCP
   - Analyzes the CSYNC flags (immediate, UseMinSOA)
   - Checks if the CSYNC has already been processed (by comparing MinSOA)
   - Queries the child zone's SOA record to ensure stability during analysis
   - Analyzes changes in NS records, A glue records, and AAAA glue records
   - Compares current delegation data with new data from the child zone
   - Updates delegation information when changes are detected

2. **CDS Scanning**: Scans zones for CDS (Child DS) records and can send
   RFC 9567 error reports.

3. **DNSKEY Scanning**: Scans zones for DNSKEY records.

4. **Periodic Operation**: Runs on a configurable interval (default: 10 seconds)
   to process scan requests.

## Design Constraints

1. The scanner operates as a background service that processes scan requests
   asynchronously.

2. CSYNC analysis follows RFC 7477 semantics:
   - Queries are performed over TCP for reliability
   - SOA stability is verified before and after analysis
   - Only in-bailiwick nameservers are analyzed for glue records
   - Changes are detected by comparing current delegation data with new data

3. The scanner maintains state about processed CSYNC records (MinSOA values)
   to avoid reprocessing the same CSYNC records.

4. Error reporting: The scanner can send RFC 9567 error reports when certain
   operations are not yet implemented (e.g., CDS scanning).

## Configuration

The scanner is configured via a YAML configuration file (default:
`tdns-scanner.yaml`). Key configuration sections include:

- `scanner.interval`: Interval in seconds between scan cycles (minimum 10 seconds)
- `apiserver`: API server configuration for receiving scan requests
- `imrengine`: Internal resolver (IMR) configuration for DNS queries
- `log.file`: Log file path
- `db.file`: Database file path for storing scanner state

## API

The scanner exposes an API endpoint `/scanner` that accepts scan requests:

- **scan**: Request an immediate scan of specified zones for a given RRtype
- **status**: Get scanner status information
