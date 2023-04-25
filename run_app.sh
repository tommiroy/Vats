#!/bin/bash
#export RUST_LOG="warn"
# Open a new terminal and run the `ls` command in it.
# xfce4-terminal -H -e 'cargo run 3000 1 0' &
# xfce4-terminal -H -e 'cargo run 3001 2 0' &
# xfce4-terminal -H -e 'cargo run 3002 3 1' &
# xfce4-terminal -H -e 'cargo run 3003 4 1' &

# gnome-terminal -- 'cargo run server -i docker_x509/central/central.pem -c docker_x509/ca/ca.crt -a 127.0.0.1 -p 3030' &
# gnome-terminal -- 'cargo run client -i docker_x509/ecu1/ecu1.pem -c docker_x509/ca/ca.crt -a 127.0.0.1 -p 3031 --caddr central --cport 3030' &
# gnome-terminal -- 'cargo run client -i docker_x509/ecu2/ecu2.pem -c docker_x509/ca/ca.crt -a 127.0.0.1 -p 3032 --caddr central --cport 3030' &
# gnome-terminal -- 'cargo run client -i docker_x509/ecu3/ecu3.pem -c docker_x509/ca/ca.crt -a 127.0.0.1 -p 3033 --caddr central --cport 3030' &

xfce4-terminal -H -e 'cargo run server -e docker_x509/central/central.pem -c docker_x509/ca/ca.crt -a 127.0.0.1 -p 3030' &
xfce4-terminal -H -e 'cargo run client -i 1 -e docker_x509/ecu1/ecu1.pem -c docker_x509/ca/ca.crt -a 127.0.0.1 -p 3031 --caddr central --cport 3030' &
xfce4-terminal -H -e 'cargo run client -i 2 -e docker_x509/ecu2/ecu2.pem -c docker_x509/ca/ca.crt -a 127.0.0.1 -p 3032 --caddr central --cport 3030' &
xfce4-terminal -H -e 'cargo run client -i 3 -e docker_x509/ecu3/ecu3.pem -c docker_x509/ca/ca.crt -a 127.0.0.1 -p 3033 --caddr central --cport 3030' &
xfce4-terminal -H -e 'cargo run client -i 4 -e docker_x509/ecu4/ecu4.pem -c docker_x509/ca/ca.crt -a 127.0.0.1 -p 3034 --caddr central --cport 3030' &
