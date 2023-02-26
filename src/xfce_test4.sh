#!/bin/bash
#export RUST_LOG="warn"
# Open a new terminal and run the `ls` command in it.
xfce4-terminal -H -e 'cargo run 3000 1 0' &
xfce4-terminal -H -e 'cargo run 3001 2 0' &
xfce4-terminal -H -e 'cargo run 3002 3 1' &
xfce4-terminal -H -e 'cargo run 3003 4 1' &
