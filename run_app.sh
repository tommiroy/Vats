#!/bin/bash
export RUST_LOG=info

xterm -hold -e 'cargo run cmd' &
xterm -hold -e 'cargo run server -e docker_x509/central/central.pem -c docker_x509/ca/ca.crt -a 127.0.0.1 -p 3030' &
xterm -hold -e 'cargo run client -i 1 -e docker_x509/ecu1/ecu1.pem -c docker_x509/ca/ca.crt -a 127.0.0.1 -p 3031 --caddr central --cport 3030' &
xterm -hold -e 'cargo run client -i 4 -e docker_x509/ecu4/ecu4.pem -c docker_x509/ca/ca.crt -a 127.0.0.1 -p 3034 --caddr central --cport 3030' &
xterm -hold -e 'cargo run client -i 2 -e docker_x509/ecu2/ecu2.pem -c docker_x509/ca/ca.crt -a 127.0.0.1 -p 3032 --caddr central --cport 3030' &
xterm -hold -e 'cargo run client -i 3 -e docker_x509/ecu3/ecu3.pem -c docker_x509/ca/ca.crt -a 127.0.0.1 -p 3033 --caddr central --cport 3030' &



# Co-authored-by: tommiroy <tommiroy@users.noreply.github.com>
