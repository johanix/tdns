#!/bin/bash
#
# Generate a self-signed TLS certificate with proper SAN entries.
# Works for both hostname-based and IP-based certs (e.g. for DoH on 127.0.0.1).
#

echo -n "Enter a short name (used for CN and filenames, e.g. ddep): "
read name

if [ -z "$name" ]; then
    echo "Name is required."
    exit 1
fi

echo -n "Enter DNS names (comma-separated, or blank to skip, e.g. ddep,tdns-imr): "
read dns_names

echo -n "Enter IP addresses (comma-separated, or blank to skip, e.g. 127.0.0.1): "
read ip_addrs

# Build the SAN string
san=""
if [ -n "$dns_names" ]; then
    IFS=',' read -ra NAMES <<< "$dns_names"
    for n in "${NAMES[@]}"; do
        n=$(echo "$n" | xargs)  # trim whitespace
        [ -n "$san" ] && san="${san},"
        san="${san}DNS:${n}"
    done
fi
if [ -n "$ip_addrs" ]; then
    IFS=',' read -ra ADDRS <<< "$ip_addrs"
    for a in "${ADDRS[@]}"; do
        a=$(echo "$a" | xargs)  # trim whitespace
        [ -n "$san" ] && san="${san},"
        san="${san}IP:${a}"
    done
fi

if [ -z "$san" ]; then
    san="DNS:${name},IP:127.0.0.1"
    echo "No SANs provided, defaulting to: $san"
fi

echo ""
echo "CN:   $name"
echo "SANs: $san"
echo ""

# Build a temporary openssl config with the requested SANs
TMPCONF=$(mktemp /tmp/openssl-san.XXXXXX.cnf)
cat > "$TMPCONF" <<EOF
[ req ]
default_bits       = 2048
distinguished_name = req_distinguished_name
req_extensions     = v3_req
x509_extensions    = v3_req
prompt             = no

[ req_distinguished_name ]
CN = ${name}

[ v3_req ]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = ${san}
EOF

echo "Generating private key and certificate..."
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${name}.key" -out "${name}.crt" \
    -days 3650 -config "$TMPCONF"

rc=$?
rm -f "$TMPCONF"

if [ $rc -eq 0 ]; then
    echo ""
    echo "Generated:"
    echo "  Key:  ${name}.key"
    echo "  Cert: ${name}.crt"
    echo ""
    echo "Verify SANs:"
    echo "  openssl x509 -in ${name}.crt -noout -ext subjectAltName"
    echo ""
    echo "Trust on macOS (for Firefox DoH, etc.):"
    echo "  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ${name}.crt"
else
    echo "Certificate generation failed."
fi
