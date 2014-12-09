#!/bin/bash
rm server
make Server
./server --port=9249
