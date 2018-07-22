#!/bin/bash

# test evocrypt as a command line tool doing encrypt/decrypt ops
# the executable can be assigned at runtime

./$1 --password $2 < test_file.txt | ./$1 --password $2 > $2.decrypted
