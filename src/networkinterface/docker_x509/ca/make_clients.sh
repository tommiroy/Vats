#!/bin/bash

read -p "Enter your name : " client

mkdir $client

openssl genrsa -out $client/$client.key 2048
openssl req -new -key $client/$client.key -addext "subjectAltName = DNS:$client" -out $client/$client.csr

# after answering the prompt above
openssl x509 -req -in $client/$client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -extfile <(printf "subjectAltName=DNS:$client") -out $client/$client.crt
cat $client/$client.crt $client/$client.key >$client/$client.pem

mv $client ..
# enter a password (e.g. 123456 (plz don't use weak password in real-world deployment))
