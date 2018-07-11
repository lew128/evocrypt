#!/bin/bash
./evocrypt.py --password Fredericko < test_file.txt 2> encrypt.tmp | \
./evocrypt.py --password Fredericko 2> decrypt.tmp
