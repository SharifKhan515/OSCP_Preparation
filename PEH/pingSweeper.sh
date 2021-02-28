#!/bin/bash

if ["$1" == ""]
then
echo "You forgot ip address"
echo "Syntax: ./pingSweeper.sh 192.168.0"
else
for port in `seq 1 254`; do
ping -c 1 $1.$port | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" &
done
fi
