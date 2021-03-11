#! /bin/sh
set -e
set -x

mkdir -p certs

openssl genrsa -out certs/rootCA.key 2048
openssl req -x509 -new -nodes -key certs/rootCA.key -days 365 -out certs/rootCA.crt \
    -subj "/CN=rootca.example.com" 

openssl genrsa -out certs/privkey.pem 2048
openssl req -new -key certs/privkey.pem -out certs/server.csr \
    -subj "/CN=nts.example.com" 
openssl x509 -req -in certs/server.csr -CA certs/rootCA.crt -CAkey certs/rootCA.key  -CAcreateserial -out certs/cert.pem -days 100

cat certs/cert.pem certs/rootCA.crt >certs/fullchain.pem
