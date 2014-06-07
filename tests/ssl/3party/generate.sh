#!/bin/bash
touch certindex
echo 000a > certserial
echo 000a > crlnumber

echo "[+] Generating CA certificate..."
openssl req -newkey rsa:4096 -sha512 -days 9999 -x509 -nodes -out ca.pem -keyout ca_privkey.pem

echo "[+] Generating client CSR..."
openssl req -newkey rsa:4096 -sha512 -nodes -out client.csr -keyout client.key

echo "[+] Signing client CSR..."
openssl ca -batch -config ca.conf -notext -in client.csr -out client.pem

echo "[+] Creating client certificate..."
cat client.key client.pem > client_full.pem


echo "[+] Generating server CSR..."
openssl req -newkey rsa:4096 -sha512 -nodes -out server.csr -keyout server.key

echo "[+] Signing server CSR..."
openssl ca -batch -config ca.conf -notext -in server.csr -out server.pem

echo "[+] Creating client certificate..."
cat server.key server.pem > server_full.pem

echo "[+] Creating CRL..."
openssl ca -config ca.conf -gencrl -keyfile ca_privkey.pem -cert ca.pem -out ca_crl.pem

echo "[+] All done."
