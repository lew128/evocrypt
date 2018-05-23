#!/bin/bash

# This script tests random large and small primes for whether they
# produce pseudo-random numbers.
#
# Algorithm is to repeat forever a basic script, adding the output
# to an existing file of results.

if [ -f evoprngs_srch_$1.stderr ]; then
    echo "file exists, choose another parameter"
    exit
fi

while :
    do
        ./evoprngs.py --password umberalertness --test search 2>> evoprngs_srch_$1.stderr | dieharder -a -g 200 >> die_evoprngs_srch_$1.stdout 2>> die_evoprngs_srch_$1.stderr 
    done

