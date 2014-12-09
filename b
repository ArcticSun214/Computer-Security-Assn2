#!/bin/bash
rm client
make Client
./client --serverAddress=10.0.2.15 --port=9249 --send ./file
