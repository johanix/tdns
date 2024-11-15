#!/bin/bash

echo -n "Enter cert common name (must end in a .): "
read cn

echo "You entered: $cn"

echo Generating private key
openssl genpkey -algorithm RSA -out ${cn}.key

echo Generating CSR
openssl req -new -key ${cn}.key -out ${cn}.csr -subj "/CN=${cn}"

echo Generating certificate
openssl x509 -req -days 3650 -in ${cn}.csr -signkey ${cn}.key -out ${cn}.crt
