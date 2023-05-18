#!/bin/bash


# make 20 clients
#read -p "Enter your name : " client
cd /home/l30/thesis/Vats/docker_x509

for i in {1..20}
do 
    client="ecu$i"

    mkdir $client 

    openssl genrsa -out $client/$client.key 2048
    openssl req -batch -new -key $client/$client.key -addext "subjectAltName = DNS:$client" -out $client/$client.csr -subj "/CN=$client"

    # after answering the prompt above
    openssl x509 -req -in $client/$client.csr -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial -extfile <(printf "subjectAltName=DNS:$client") -out $client/$client.crt
    cat $client/$client.crt $client/$client.key ca/ca.crt >$client/$client.pem

done

