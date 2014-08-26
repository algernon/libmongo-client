SSL=$(shell which openssl)
CA_CONF=ca.conf
ALL_FILES=certindex certserial crlnumber ca.pem ca_privkey.pem client.pem client.csr client.key client_full.pem server.csr server.pem server.key server_full.pem ca_crl.pem server.sign server.dn

mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
current_dir := $(patsubst %/,%,$(dir $(mkfile_path)))

all: $(ALL_FILES)

certindex:
	touch $@

certserial:
	echo 000a > $@

crlnumber:
	echo 000a > $@

ca.pem:
	$(SSL) req -newkey rsa:4096 -sha512 -days 9999 -x509 -nodes -out $@ -keyout ca_privkey.pem

client.csr:
	$(SSL) req -newkey rsa:4096 -sha512 -nodes -out $@ -passin pass:test_client -keyout client.key

client.pem: client.csr
	$(SSL) ca -batch -config $(CA_CONF) -notext -in $< -out $@

client_full.pem: client.key client.pem
	cat client.pem client.key > $@

server.csr:
	$(SSL) req -newkey rsa:4096 -sha512 -nodes -out server.csr -keyout server.key

server.pem: server.csr
	$(SSL) ca -batch -config $(CA_CONF) -notext -in $< -out $@

server.sign: server.pem
	$(SSL) x509 -sha1 -in $< -noout -fingerprint | sed 's/ Fingerprint=/:/' > $@

server.dn: server.pem
	$(SSL) x509 -in $< -noout -subject -nameopt RFC2253 | sed 's/subject= //' > $@

server_full.pem: server.key server.pem
	cat server.pem server.key > $@

ca_crl.pem: ca.pem ca_privkey.pem
	$(SSL) ca -config $(CA_CONF) -gencrl -keyfile ca_privkey.pem -cert ca.pem -out ca_crl.pem

revoke: server.pem ca_privkey.pem ca.pem
	$(SSL) ca -config $(CA_CONF) -revoke server.pem -keyfile ca_privkey.pem -cert ca.pem
	$(SSL) ca -config $(CA_CONF) -gencrl -keyfile ca_privkey.pem -cert ca.pem -out ca_crl.pem
	

clean:
	rm -f $(ALL_FILES)
	rm -f *.attr
	rm -f *.old
	rm -f 0A.pem
	rm -f 0B.pem
	rm -f mongodb-ssl.conf

config:
	echo "port = 27017" > mongodb-ssl.conf
	echo "sslMode = preferSSL" >> mongodb-ssl.conf
	echo "sslPEMKeyFile = $(current_dir)/server_full.pem" >> mongodb-ssl.conf
	echo "sslCAFile = $(current_dir)/ca.pem" >> mongodb-ssl.conf

.PHONY: clean revoke config
