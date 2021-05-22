#!/bin/bash

if [ $# -lt 1 ]; then
    # TODO: print usage
    echo missing domain
    exit 1
fi
#mkdir ~/.mitmproxy/certs
echo domain: $1
cp certificate.conf /tmp/temp_${1}_conf.conf
sed -i "s/DOMAINNAME/${1}/g" /tmp/temp_${1}_conf.conf
#openssl genrsa -out superkey.key 2048
openssl req -new -key ~/.mitmproxy/certs/superkey.key -out ~/.mitmproxy/certs/${1}.csr -config /tmp/temp_${1}_conf.conf
openssl x509 -req -extfile /tmp/temp_${1}_conf.conf -extensions req_ext -in ~/.mitmproxy/certs/${1}.csr -CA ~/.mitmproxy/mitmproxy-ca.pem -CAkey ~/.mitmproxy/mitmproxy-ca.pem -CAcreateserial -out ~/.mitmproxy/certs/${1}.tmp.crt -days 200 -sha256
cat ~/.mitmproxy/certs/${1}.tmp.crt ~/.mitmproxy/mitmproxy-ca-cert.cer > ~/.mitmproxy/certs/${1}.crt
rm ~/.mitmproxy/certs/${1}.tmp.crt ~/.mitmproxy/certs/${1}.csr /tmp/temp_${1}_conf.conf
