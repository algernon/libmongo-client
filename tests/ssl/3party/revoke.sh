#!/bin/bash
openssl ca -config ca.conf -revoke server.pem -keyfile ca_privkey.pem -cert ca.pem
openssl ca -config ca.conf -gencrl -keyfile ca_privkey.pem -cert ca.pem -out ca_crl.pem
openssl crl -inform PEM -in ca_crl.pem -outform DER -out ca_crl.der
