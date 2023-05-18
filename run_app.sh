#!/bin/bash
export RUST_LOG=info

xterm -hold -e 'cargo run cmd' &
xterm -hold -e 'cargo run server -e docker_x509/central/central.pem -c docker_x509/ca/ca.crt -a 127.0.0.1 -p 3030' &

for i in {1..20}
do
    # start a termnial for each i to run the client
    port=$((3030 + i))

    xterm -hold -e "cargo run client -i $i -e docker_x509/ecu$i/ecu$i.pem -c docker_x509/ca/ca.crt -a 127.0.0.1 -p $port --caddr central --cport 3030" &
done
    

# Co-authored-by: tommiroy <tommiroy@users.noreply.github.com>

